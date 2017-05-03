/**
 * Proportional Delay Differentiation (PDD) Scheduler
 * Written during 2012-03 by Rob Jansen <jansen@cs.umn.edu>
 *
 * A hybrid scheduler combining the "Proportional Average Delay" and "Waiting
 * Time Priority" Schedulers from:
 * "Proportional Differentiated Services: Delay Differentiation and Packet
 * Scheduling", Drovolis et al. IEEE/ACM Transactions on Networking, Volume 10,
 * Number 1, February 2002.
 *
 * A scheduler that selects the next circuit based on proportional average
 * delay of the circuit and waiting time of the head of each service class.
 * The scheduler computes the priority of the head of each service class,
 * following the proportional differentiation model of Drovolis, et al. The
 * configured delay differentiation parameters DDP are used for each class i,
 * and priority p for class i is computed as
 *   p_i = waiting_time_i / DDP_i
 * for WTP (where waiting_time_i is the waiting time of the head of i) and
 *   p_i = delay_sent / total_sent / DDP_i
 * for PAD (where delay_sent/total_sent is the normalized average delay of i).
 * The highest priority circuit is selected.
 */

#include <math.h>
#include <stdint.h>
#include "or.h"
#include "config.h"
#include "container.h"
#include "relay.h"
#include "scheduler.h"

typedef struct cell_ewma_s cell_ewma_t;
typedef struct scheduleritem_pdd_s scheduleritem_pdd_t;
typedef struct service_class_s service_class_t;
#define ONESEC 1000000L

struct cell_ewma_s {
  int pqueue_index;
  double cell_count_ewma;
  unsigned last_adjusted_tick;
  scheduleritem_pdd_t *item;
  service_class_t *class;
};

struct service_class_s {
  smartlist_t *active_pqueue;
  double ewma2; /* ewma of the cell ewmas */
  unsigned int ewma2_last_adjusted_tick;
  size_t n;
};

/**
 * State specific to the PDD scheduler
 * This extends scheduler_s
 */
struct scheduler_pdd_s {
  scheduler_t _base;

  service_class_t paid_class;
  service_class_t unpaid_class;

  unsigned int ewma_current_tick;
  double ewma_scale_factor;
};


struct scheduleritem_pdd_s {
  scheduleritem_t _base;

  cell_ewma_t n_ewma;
  cell_ewma_t p_ewma;

  /* the number of prioritized cells we have left to send */
  size_t num_prioritized_remaining;
  /* if we are eligable to increase our priority cell counter */
  int is_eligible;
};

/** Helper for sorting cell_ewma_t values in their priority queue. */
static int
compare_cell_ewma_counts(const void *p1, const void *p2)
{
  const cell_ewma_t *e1=p1, *e2=p2;

  tor_assert(e1);
  tor_assert(e2);

  if (e1->cell_count_ewma < e2->cell_count_ewma)
    return -1;
  else if (e1->cell_count_ewma > e2->cell_count_ewma)
    return 1;
  else
    return 0;
}

/** helper to get the correct timestamp queue associated with the given
 * scheduler and item. This determines the correct queue based on if the item
 * corresponds to n_conn or p_conn.
 * @param scheduler an orconn scheduler
 * @param item a circuit scheduler state item
 * @return timestamp queue associated with the circuit's n_conn or p_conn
 */
static INLINE cell_ewma_t *get_cell_ewma(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);
  or_connection_t *orconn = scheduler->_base.orconn;
  tor_assert(orconn);
  circuit_t *circ = item->_base.circ;
  tor_assert(circ);
  if (circ->n_conn == orconn) {
    return &(item->n_ewma);
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(orcirc->p_conn == orconn);
    return &(item->p_ewma);
  }
}

#define TICK_LEN 1
static unsigned int tick_from_timeval(const struct timeval *now,
                            double *remainder_out)
{
  unsigned res = (unsigned) (now->tv_sec / TICK_LEN);
  /* rem */
  double rem = (now->tv_sec % TICK_LEN) +
    ((double)(now->tv_usec)) / 1.0e6;
  *remainder_out = rem / TICK_LEN;
  return res;
}

/** Compute and return the current cell_ewma tick. */
unsigned int get_tick(void)
{
  return ((unsigned)approx_time() / TICK_LEN);
}

/** Return the multiplier necessary to convert the value of a cell sent in
 * 'from_tick' to one sent in 'to_tick'. */
static INLINE double scheduler_pdd_get_scale_factor(scheduler_pdd_t *scheduler,
    unsigned from_tick, unsigned to_tick) {
  tor_assert(scheduler);
  /* This math can wrap around, but that's okay: unsigned overflow is
     well-defined */
  int diff = (int)(to_tick - from_tick);
  return pow(scheduler->ewma_scale_factor, diff);
}

/** Adjust the cell count of <b>ewma</b> so that it is scaled with respect to
 * <b>cur_tick</b> */
static void scheduleritem_pdd_scale(scheduler_pdd_t *scheduler,
    cell_ewma_t *e, unsigned int cur_tick) {
  tor_assert(e);
  tor_assert(e->item);

  /* scale the circuit ema */
  double factor = scheduler_pdd_get_scale_factor(scheduler,
    e->last_adjusted_tick, cur_tick);
  e->cell_count_ewma *= factor;
  e->last_adjusted_tick = cur_tick;
}

/** Adjust the cell count of every active circuit and class so
 * that they are scaled with respect to <b>cur_tick</b> */
static void scheduler_pdd_scale(scheduler_pdd_t *scheduler,
    unsigned int cur_tick) {
  double factor;
  tor_assert(scheduler);

//  /* scale the paid class ewma */
//  factor = scheduler_pdd_get_scale_factor(scheduler,
//	  scheduler->paid_class.ewma2_last_adjusted_tick, cur_tick);
//  scheduler->paid_class.ewma2 *= factor;
//  scheduler->paid_class.ewma2_last_adjusted_tick = cur_tick;
//
//  /* scale the unpaid class ewma */
//  factor = scheduler_pdd_get_scale_factor(scheduler,
//	  scheduler->unpaid_class.ewma2_last_adjusted_tick, cur_tick);
//  scheduler->unpaid_class.ewma2 *= factor;
//  scheduler->unpaid_class.ewma2_last_adjusted_tick = cur_tick;

  factor = scheduler_pdd_get_scale_factor(scheduler,
		  scheduler->ewma_current_tick, cur_tick);

  SMARTLIST_FOREACH(scheduler->paid_class.active_pqueue, cell_ewma_t *, e,
	e->cell_count_ewma *= factor;
    e->last_adjusted_tick = cur_tick;
  );

  SMARTLIST_FOREACH(scheduler->unpaid_class.active_pqueue, cell_ewma_t *, e,
	e->cell_count_ewma *= factor;
    e->last_adjusted_tick = cur_tick;
  );

  scheduler->ewma_current_tick = cur_tick;
}

static void scheduler_pdd_activate_cell_ewma(scheduler_pdd_t *scheduler,
    cell_ewma_t *e) {
  tor_assert(scheduler);
  tor_assert(e);

  /* it must not be active (exist in the pqueue) if we are adding it */
  tor_assert(e->pqueue_index == -1);

  if(e->item->num_prioritized_remaining > 0)
    e->class = &scheduler->paid_class;
  else
    e->class = &scheduler->unpaid_class;

  tor_assert(e->class);

  /* we just became active, so make sure our tick matches the schedulers */
  scheduleritem_pdd_scale(scheduler, e, scheduler->ewma_current_tick);

  /* activated means in the pqueue so it can be selected for scheduling */
  smartlist_pqueue_add(e->class->active_pqueue, compare_cell_ewma_counts,
    STRUCT_OFFSET(cell_ewma_t, pqueue_index), e);

  tor_assert(e->pqueue_index != -1);
}

static void scheduler_pdd_deactivate_cell_ewma(scheduler_pdd_t *scheduler,
		cell_ewma_t *e) {
  tor_assert(scheduler);
  tor_assert(e);

  /* it must be active (exist in the pqueue) in order to remove it */
  tor_assert(e->pqueue_index != -1);
  tor_assert(e->class);

  /* deactivated means not in the pqueue so its not selected for scheduling */
  smartlist_pqueue_remove(e->class->active_pqueue, compare_cell_ewma_counts,
    STRUCT_OFFSET(cell_ewma_t, pqueue_index), e);

  tor_assert(e->pqueue_index == -1);
  e->class = NULL;
}

static void scheduler_pdd_free(scheduler_pdd_t *scheduler) {
  tor_assert(scheduler);
  smartlist_free(scheduler->paid_class.active_pqueue);
  smartlist_free(scheduler->unpaid_class.active_pqueue);
  tor_free(scheduler);
}

static scheduleritem_pdd_t *
scheduler_pdd_select_item(scheduler_pdd_t *scheduler) {
  tor_assert(scheduler);

  struct timeval now;
  tor_gettimeofday_cached(&now);

  /* update ema if needed */
  double fractional_tick;
  unsigned int tick = tick_from_timeval(&now, &fractional_tick);
  if (tick != scheduler->ewma_current_tick) {
    scheduler_pdd_scale(scheduler, tick);
  }

  int npaid = smartlist_len(scheduler->paid_class.active_pqueue);
  int nunpaid = smartlist_len(scheduler->unpaid_class.active_pqueue);

  if (npaid > 0 && nunpaid > 0) {
    const or_options_t* opts = get_options();
    double weight = opts->LiraWeight;
    double diff_factor = opts->LiraFactor;
    double diff_constant = (double) opts->LiraConstant;

    cell_ewma_t *paide = smartlist_get(scheduler->paid_class.active_pqueue, 0);
    cell_ewma_t *unpaide = smartlist_get(scheduler->unpaid_class.active_pqueue, 0);

    double paid_priority = (paide->cell_count_ewma * weight) +
        (scheduler->paid_class.ewma2 * (1.0 - weight));
    double unpaid_priority = (unpaide->cell_count_ewma * weight) +
        (scheduler->unpaid_class.ewma2 * (1.0 - weight));

    unpaid_priority *= diff_factor;
    unpaid_priority += (diff_constant / CELL_NETWORK_SIZE);

    if(paid_priority < unpaid_priority)
      return paide->item;
    else
      return unpaide->item;
  } else if (npaid > 0) {
    cell_ewma_t *e = smartlist_get(scheduler->paid_class.active_pqueue, 0);
    return e->item;
  } else if (nunpaid > 0) {
    cell_ewma_t *e = smartlist_get(scheduler->unpaid_class.active_pqueue, 0);
    return e->item;
  } else {
    return NULL;
  }
}

static void scheduler_pdd_item_scheduled_callback(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  /* the queue we've been scheduling may need to change position in the pqueue */
  cell_ewma_t *e = get_cell_ewma(scheduler, item);
  tor_assert(e);

  /* we just scheduled several cells from tsq */
  if(e->pqueue_index != -1) {
    /* tsq is still active, so we need to ensure the pqueue is sorted */
    scheduler_pdd_deactivate_cell_ewma(scheduler, e);
    scheduler_pdd_activate_cell_ewma(scheduler, e);
  }
}

static void scheduler_pdd_activate_item(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  /* only activate it if its not already active */
  cell_ewma_t *e = get_cell_ewma(scheduler, item);
  if(e->pqueue_index == -1)
    scheduler_pdd_activate_cell_ewma(scheduler, e);
}

static void scheduler_pdd_deactivate_item(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  /* only deactivate it if its active */
  cell_ewma_t *e = get_cell_ewma(scheduler, item);
  if(e->pqueue_index != -1)
    scheduler_pdd_deactivate_cell_ewma(scheduler, e);
}

static void scheduler_pdd_cell_added_callback(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  cell_ewma_t *e = get_cell_ewma(scheduler, item);
  tor_assert(e);
  return;
}

static int scheduler_pdd_cell_removed_callback(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  cell_ewma_t *e = get_cell_ewma(scheduler, item);
  tor_assert(e);

  struct timeval now;
  tor_gettimeofday_cached(&now);

  /* get the EWMA values so we know how to increment */
  double fractional_tick;
  tick_from_timeval(&now, &fractional_tick);
  double increment = pow(scheduler->ewma_scale_factor, -fractional_tick);

  /* update circuit cell count ema, essentially (increment * 1 cell) */
  e->cell_count_ewma += increment;
  /* update class delay ewma of the circuit ewmas*/
  tor_assert(e->class);
  e->class->ewma2 = ((e->class->ewma2 * e->class->n) + e->cell_count_ewma) / (e->class->n + 1);
  e->class->n++;

  /* do we need to lose priority */
  if(item->num_prioritized_remaining > 0) {
    (item->num_prioritized_remaining)--;
    if(item->num_prioritized_remaining == 0)
      if(e->pqueue_index != -1) {
        scheduler_pdd_deactivate_cell_ewma(scheduler, e);
        scheduler_pdd_activate_cell_ewma(scheduler, e);
        tor_assert(e->pqueue_index != -1);
      }
  }

  return 0;
}

static void scheduler_pdd_unlink_active_items(scheduler_pdd_t *scheduler) {
  tor_assert(scheduler);

  SMARTLIST_FOREACH(scheduler->paid_class.active_pqueue, cell_ewma_t *, e,
    e->pqueue_index = -1;
  );
  smartlist_clear(scheduler->paid_class.active_pqueue);

  SMARTLIST_FOREACH(scheduler->unpaid_class.active_pqueue, cell_ewma_t *, e,
    e->pqueue_index = -1;
  );
  smartlist_clear(scheduler->unpaid_class.active_pqueue);
}

static void scheduler_pdd_assert_active_items(scheduler_pdd_t *scheduler) {
  tor_assert(scheduler);
  SMARTLIST_FOREACH(scheduler->paid_class.active_pqueue, cell_ewma_t *, e,
    tor_assert(e->pqueue_index != -1);
  );
  SMARTLIST_FOREACH(scheduler->unpaid_class.active_pqueue, cell_ewma_t *, e,
    tor_assert(e->pqueue_index != -1);
  );
}

static int scheduler_pdd_is_active(scheduler_pdd_t *scheduler) {
  tor_assert(scheduler);
  if (smartlist_len(scheduler->paid_class.active_pqueue) > 0 ||
		smartlist_len(scheduler->unpaid_class.active_pqueue) > 0)
    return 1;
  else
    return 0;
}

static void scheduler_pdd_configure_priority(scheduler_pdd_t *scheduler,
    scheduleritem_pdd_t *item, int is_prioritized, size_t ncells) {
  tor_assert(scheduler);
  tor_assert(item);

  /*
   * if is_prioritized, this message is telling us we were 'payed' to prioritize
   * ncells additional cells. otherwise, this tells us that ncells more cells
   * have to be sent before another 'payed' message should be processed. for
   * purposes of our simulation, we ignore the second case.
   */

  if(is_prioritized && item->is_eligible) {
    (item->num_prioritized_remaining) += ncells;
    cell_ewma_t *e = get_cell_ewma(scheduler, item);
    if(e->pqueue_index != -1) {
      scheduler_pdd_deactivate_cell_ewma(scheduler, e);
      scheduler_pdd_activate_cell_ewma(scheduler, e);
    }
  } else {
    item->is_eligible = 0;
  }
}

scheduler_pdd_t *scheduler_pdd_new(or_connection_t *orconn) {
  scheduler_pdd_t *scheduler = tor_malloc_zero(sizeof(scheduler_pdd_t));

  /* TODO: this could move to a scheduler_init() func since its common among
   * all schedulers. */
  scheduler->_base.orconn = orconn;
  scheduler->_base.type = SCHEDULER_TYPE_PDD;

  scheduler->_base.free = (scheduler_free_func) scheduler_pdd_free;
  scheduler->_base.select_item =
    (scheduler_select_item_func) scheduler_pdd_select_item;
  scheduler->_base.cell_added =
    (scheduler_cell_added_callback_func) scheduler_pdd_cell_added_callback;
  scheduler->_base.cell_removed =
    (scheduler_cell_removed_callback_func) scheduler_pdd_cell_removed_callback;
  scheduler->_base.item_scheduled =
    (scheduler_item_scheduled_callback_func) scheduler_pdd_item_scheduled_callback;
  scheduler->_base.activate_item =
    (scheduler_activate_item_func) scheduler_pdd_activate_item;
  scheduler->_base.deactivate_item =
      (scheduler_deactivate_item_func) scheduler_pdd_deactivate_item;
  scheduler->_base.unlink_active_items =
      (scheduler_unlink_active_items_func) scheduler_pdd_unlink_active_items;
  scheduler->_base.assert_active_items =
      (scheduler_assert_active_items_func) scheduler_pdd_assert_active_items;
  scheduler->_base.is_active =
      (scheduler_is_active_func) scheduler_pdd_is_active;
  scheduler->_base.configure_priority =
      (scheduler_configure_priority_func) scheduler_pdd_configure_priority;

  /* initialize our service classes */
  scheduler->paid_class.active_pqueue = smartlist_new();
  scheduler->unpaid_class.active_pqueue = smartlist_new();

  scheduler->ewma_scale_factor = exp((double)((-0.69314718055994529)/(30.0/TICK_LEN)));

  log_notice(LD_OR,
           "Enabled Proportional EWMA Differentiation algorithm; "
           "scale factor is %f per %d seconds",
           scheduler->ewma_scale_factor, TICK_LEN);

  scheduler->ewma_current_tick = get_tick();

  return scheduler;
}

static void scheduleritem_pdd_free(scheduleritem_pdd_t *item) {
  tor_assert(item);
  tor_free(item);
}

static int scheduleritem_pdd_is_active_outward(scheduleritem_pdd_t *item) {
  tor_assert(item);
  return item->n_ewma.pqueue_index != -1;
}

static int scheduleritem_pdd_is_active_inward(scheduleritem_pdd_t *item) {
  tor_assert(item);
  return item->p_ewma.pqueue_index != -1;
}

scheduleritem_pdd_t *scheduleritem_pdd_new(circuit_t *circ) {
  scheduleritem_pdd_t * item = tor_malloc_zero(sizeof(scheduleritem_pdd_t));

  item->_base.circ = circ;
  item->_base.type = SCHEDULER_TYPE_PDD;

  item->_base.free = (scheduleritem_free_func) scheduleritem_pdd_free;
  item->_base.is_active_outward =
    (scheduleritem_is_active_outward_func) scheduleritem_pdd_is_active_outward;
  item->_base.is_active_inward =
    (scheduleritem_is_active_inward_func) scheduleritem_pdd_is_active_inward;

  /* start out inactive, i.e. not inside of a priority queue */
  item->n_ewma.pqueue_index = -1;
  item->p_ewma.pqueue_index = -1;

  /* give a link back to the item for scheduling */
  item->n_ewma.item = item;
  item->p_ewma.item = item;

  item->is_eligible = 1;

  return item;
}
