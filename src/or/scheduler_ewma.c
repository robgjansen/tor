/**
 * This is a quick attempt at modularizing the Tor scheduling infrastructure.
 * Code adapted from relay.c on 2012-03-19 by Rob Jansen <jansen@cs.umn.edu>
 */

#include <math.h>
#include "or.h"
#include "config.h"
#include "networkstatus.h"
#include "relay.h"
#include "scheduler.h"

/**
 * State specific to the round-robin scheduler
 * This extends scheduler_s
 */
struct scheduler_ewma_s {
  scheduler_t _base;

  /** Priority queue of cell_ewma_t for circuits with queued cells waiting for
   * room to free up on this connection's outbuf.  Kept in heap order
   * according to EWMA.
   *
   * This is redundant with active_circuits; if we ever decide only to use the
   * cell_ewma algorithm for choosing circuits, we can remove active_circuits.
   */
  smartlist_t *active_circuit_pqueue;

  /** The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled. */
  unsigned active_circuit_pqueue_last_recalibrated;

  /** a temporary ewma increment value for cells being scheduled in a given
   * 'round' (multiple cells written per scheduling decision), or -1 if we are
   * not in the middle of a scheduling 'round' */
  double current_ewma_increment;
};

typedef struct {
  /** The last 'tick' at which we recalibrated cell_count.
   *
   * A cell sent at exactly the start of this tick has weight 1.0. Cells sent
   * since the start of this tick have weight greater than 1.0; ones sent
   * earlier have less weight. */
  unsigned last_adjusted_tick;

  /** The EWMA of the cell count. */
  double cell_count;
  double adjusted_cell_count;

  /** pointer to the parent scheduleritem_t* holding this cell_ewma_t */
  scheduleritem_ewma_t *item;

  /** The position of the circuit within the OR connection's priority
   * queue. */
  int heap_index;
} cell_ewma_t;

/**
 * The cell_ewma_t structure keeps track of how many cells a circuit has
 * transferred recently.  It keeps an EWMA (exponentially weighted moving
 * average) of the number of cells flushed from the circuit queue onto a
 * connection in connection_or_flush_from_first_active_circuit().
 */
struct scheduleritem_ewma_s {
  scheduleritem_t _base;

  /** The EWMA count for the number of cells flushed from the
   * n_conn_cells queue.  Used to determine which circuit to flush from next.
   */
  cell_ewma_t n_cell_ewma;

  /** The EWMA count for the number of cells flushed from the
   * p_conn_cells queue.
   */
  cell_ewma_t p_cell_ewma;

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

  if (e1->adjusted_cell_count < e2->adjusted_cell_count)
    return -1;
  else if (e1->adjusted_cell_count > e2->adjusted_cell_count)
    return 1;
  else
    return 0;
}

/* ==== Functions for scaling cell_ewma_t ====

   When choosing which cells to relay first, we favor circuits that have been
   quiet recently.  This gives better latency on connections that aren't
   pushing lots of data, and makes the network feel more interactive.

   Conceptually, we take an exponentially weighted mean average of the number
   of cells a circuit has sent, and allow active circuits (those with cells to
   relay) to send cells in reverse order of their exponentially-weighted mean
   average (EWMA) cell count.  [That is, a cell sent N seconds ago 'counts'
   F^N times as much as a cell sent now, for 0<F<1.0, and we favor the
   circuit that has sent the fewest cells]

   If 'double' had infinite precision, we could do this simply by counting a
   cell sent at startup as having weight 1.0, and a cell sent N seconds later
   as having weight F^-N.  This way, we would never need to re-scale
   any already-sent cells.

   To prevent double from overflowing, we could count a cell sent now as
   having weight 1.0 and a cell sent N seconds ago as having weight F^N.
   This, however, would mean we'd need to re-scale *ALL* old circuits every
   time we wanted to send a cell.

   So as a compromise, we divide time into 'ticks' (currently, 10-second
   increments) and say that a cell sent at the start of a current tick is
   worth 1.0, a cell sent N seconds before the start of the current tick is
   worth F^N, and a cell sent N seconds after the start of the current tick is
   worth F^-N.  This way we don't overflow, and we don't need to constantly
   rescale.
 */

/** How long does a tick last (seconds)? */
#define EWMA_TICK_LEN 10

/** The default per-tick scale factor, if it hasn't been overridden by a
 * consensus or a configuration setting.  zero means "disabled". */
#define EWMA_DEFAULT_HALFLIFE 0.0

/** Given a timeval <b>now</b>, compute the cell_ewma tick in which it occurs
 * and the fraction of the tick that has elapsed between the start of the tick
 * and <b>now</b>.  Return the former and store the latter in
 * *<b>remainder_out</b>.
 *
 * These tick values are not meant to be shared between Tor instances, or used
 * for other purposes. */
static unsigned
cell_ewma_tick_from_timeval(const struct timeval *now,
                            double *remainder_out)
{
  unsigned res = (unsigned) (now->tv_sec / EWMA_TICK_LEN);
  /* rem */
  double rem = (now->tv_sec % EWMA_TICK_LEN) +
    ((double)(now->tv_usec)) / 1.0e6;
  *remainder_out = rem / EWMA_TICK_LEN;
  return res;
}

/** Compute and return the current cell_ewma tick. */
unsigned
cell_ewma_get_tick(void)
{
  return ((unsigned)approx_time() / EWMA_TICK_LEN);
}

/** The per-tick scale factor to be used when computing cell-count EWMA
 * values.  (A cell sent N ticks before the start of the current tick
 * has value ewma_scale_factor ** N.)
 */
static double ewma_scale_factor = 0.1;
static int ewma_enabled = 0;

#define EPSILON 0.00001
#define LOG_ONEHALF -0.69314718055994529

/** Adjust the global cell scale factor based on <b>options</b> */
void
cell_ewma_set_scale_factor(const or_options_t *options,
                           const networkstatus_t *consensus)
{
  int32_t halflife_ms;
  double halflife;
  const char *source;
  if (options && options->CircuitPriorityHalflife >= -EPSILON) {
    halflife = options->CircuitPriorityHalflife;
    source = "CircuitPriorityHalflife in configuration";
  } else if (consensus && (halflife_ms = networkstatus_get_param(
                 consensus, "CircuitPriorityHalflifeMsec",
                 -1, -1, INT32_MAX)) >= 0) {
    halflife = ((double)halflife_ms)/1000.0;
    source = "CircuitPriorityHalflifeMsec in consensus";
  } else {
    halflife = EWMA_DEFAULT_HALFLIFE;
    source = "Default value";
  }

  if (halflife <= EPSILON) {
    /* The cell EWMA algorithm is disabled. */
    ewma_scale_factor = 0.1;
    ewma_enabled = 0;
    log_info(LD_OR,
             "Disabled cell_ewma algorithm because of value in %s",
             source);
  } else {
    /* convert halflife into halflife-per-tick. */
    halflife /= EWMA_TICK_LEN;
    /* compute per-tick scale factor. */
    ewma_scale_factor = exp( LOG_ONEHALF / halflife );
    ewma_enabled = 1;
    log_info(LD_OR,
             "Enabled cell_ewma algorithm because of value in %s; "
             "scale factor is %f per %d seconds",
             source, ewma_scale_factor, EWMA_TICK_LEN);
  }
}

/** Return the multiplier necessary to convert the value of a cell sent in
 * 'from_tick' to one sent in 'to_tick'. */
static INLINE double
get_scale_factor(unsigned from_tick, unsigned to_tick)
{
  /* This math can wrap around, but that's okay: unsigned overflow is
     well-defined */
  int diff = (int)(to_tick - from_tick);
  return pow(ewma_scale_factor, diff);
}

/** Adjust the cell count of <b>ewma</b> so that it is scaled with respect to
 * <b>cur_tick</b> */
static void
scale_single_cell_ewma(cell_ewma_t *ewma, unsigned cur_tick)
{
  double factor = get_scale_factor(ewma->last_adjusted_tick, cur_tick);
  ewma->cell_count *= factor;
  ewma->last_adjusted_tick = cur_tick;

  /* if we do not have priority, add in adjustments */
  const or_options_t* opts = get_options();
  ewma->adjusted_cell_count = ewma->cell_count;
//  if(ewma->item->num_prioritized_remaining > 0 &&
//      opts->LiraPaidProbability > 0.0) {
//    ewma->adjusted_cell_count *= (1.0/opts->LiraFactor);
//    ewma->adjusted_cell_count -= (opts->LiraConstant / CELL_NETWORK_SIZE);
//  }
}

/** Rescale <b>ewma</b> to the same scale as <b>conn</b>, and add it to
 * <b>conn</b>'s priority queue of active circuits */
static void
add_cell_ewma_to_conn(scheduler_ewma_t *scheduler, cell_ewma_t *ewma)
{
  tor_assert(ewma->heap_index == -1);
  scale_single_cell_ewma(ewma,
      scheduler->active_circuit_pqueue_last_recalibrated);

  smartlist_pqueue_add(scheduler->active_circuit_pqueue,
                       compare_cell_ewma_counts,
                       STRUCT_OFFSET(cell_ewma_t, heap_index),
                       ewma);
}

/** Remove <b>ewma</b> from <b>conn</b>'s priority queue of active circuits */
static void
remove_cell_ewma_from_conn(scheduler_ewma_t *scheduler, cell_ewma_t *ewma)
{
  tor_assert(ewma->heap_index != -1);
  smartlist_pqueue_remove(scheduler->active_circuit_pqueue,
                          compare_cell_ewma_counts,
                          STRUCT_OFFSET(cell_ewma_t, heap_index),
                          ewma);
}

/** Remove and return the first cell_ewma_t from conn's priority queue of
 * active circuits.  Requires that the priority queue is nonempty. */
static cell_ewma_t *
pop_first_cell_ewma_from_conn(scheduler_ewma_t *scheduler)
{
  return smartlist_pqueue_pop(scheduler->active_circuit_pqueue,
                              compare_cell_ewma_counts,
                              STRUCT_OFFSET(cell_ewma_t, heap_index));
}

/** Adjust the cell count of every active circuit on <b>conn</b> so
 * that they are scaled with respect to <b>cur_tick</b> */
static void
scale_active_circuits(scheduler_ewma_t *scheduler, unsigned cur_tick)
{
  double factor = get_scale_factor(
      scheduler->active_circuit_pqueue_last_recalibrated,
              cur_tick);

  const or_options_t* opts = get_options();
  smartlist_t* new_pqueue = smartlist_new();

  while(scheduler->active_circuit_pqueue->num_used > 0) {
    cell_ewma_t *e = pop_first_cell_ewma_from_conn(scheduler);

    tor_assert(e->last_adjusted_tick ==
        scheduler->active_circuit_pqueue_last_recalibrated);
    e->cell_count *= factor;
    e->last_adjusted_tick = cur_tick;

    /* if we do not have priority, add in adjustments */
    e->adjusted_cell_count = e->cell_count;

//    if(e->item->num_prioritized_remaining > 0 &&
//        opts->LiraPaidProbability > 0.0) {
//      e->adjusted_cell_count *= (1.0/opts->LiraFactor);
//      e->adjusted_cell_count -= (opts->LiraConstant / CELL_NETWORK_SIZE);
//    }

    smartlist_pqueue_add(new_pqueue,
                         compare_cell_ewma_counts,
                         STRUCT_OFFSET(cell_ewma_t, heap_index),
                         e);
  }

  smartlist_free(scheduler->active_circuit_pqueue);
  scheduler->active_circuit_pqueue = new_pqueue;
  scheduler->active_circuit_pqueue_last_recalibrated = cur_tick;
}

static void scheduler_ewma_free(scheduler_ewma_t *scheduler) {
  tor_assert(scheduler);
  smartlist_free(scheduler->active_circuit_pqueue);
  tor_free(scheduler);
}

static scheduleritem_ewma_t* scheduler_ewma_select_item(scheduler_ewma_t *scheduler) {
  tor_assert(scheduler);

  unsigned tick;
  double fractional_tick;

  /* The EWMA cell counter for the circuit we're flushing. */
  cell_ewma_t *cell_ewma = NULL;

  /* The current (hi-res) time */
  struct timeval now_hires;

  tor_gettimeofday_cached(&now_hires);
  tick = cell_ewma_tick_from_timeval(&now_hires, &fractional_tick);

  if (tick != scheduler->active_circuit_pqueue_last_recalibrated) {
    scale_active_circuits(scheduler, tick);
  }

  /* store our ewma increment for all cells sent in this round */
  scheduler->current_ewma_increment = pow(ewma_scale_factor, -fractional_tick);

  cell_ewma = smartlist_get(scheduler->active_circuit_pqueue, 0);
  tor_assert(cell_ewma->item);
  return cell_ewma->item;
}

static void scheduler_ewma_cell_added_callback(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t* item) {
  /* do nothing */
  return;
}

static int scheduler_ewma_cell_removed_callback(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  /* We pop and re-add the cell_ewma_t here, not above, since we need to
   * re-add it immediately to keep the priority queue consistent with
   * the linked-list implementation */
  cell_ewma_t *ewma = pop_first_cell_ewma_from_conn(scheduler);

  tor_assert(ewma);
  tor_assert((ewma == &(item->n_cell_ewma)) || (ewma == &(item->p_cell_ewma)));
  tor_assert(scheduler->current_ewma_increment != -1);

  if(item->num_prioritized_remaining > 0) {
    (item->num_prioritized_remaining)--;
  }

  /* increment cell count by our current round's computed increment */
  ewma->cell_count += scheduler->current_ewma_increment;

  add_cell_ewma_to_conn(scheduler, ewma);

  return 0;
}

static void scheduler_ewma_item_scheduled_callback(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t* item) {
  /* this round is over, reset the increment */
  scheduler->current_ewma_increment = -1;
}

static void scheduler_ewma_activate_item(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  or_connection_t *orconn = scheduler->_base.orconn;
  circuit_t *circ = item->_base.circ;

  if (circ->n_conn == orconn) {
    add_cell_ewma_to_conn(scheduler, &(item->n_cell_ewma));
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(orcirc->p_conn == orconn);
    add_cell_ewma_to_conn(scheduler, &(item->p_cell_ewma));
  }

  assert_active_circuits_ok_paranoid(orconn);
}

static void scheduler_ewma_deactivate_item(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  or_connection_t *orconn = scheduler->_base.orconn;
  circuit_t *circ = item->_base.circ;

  if (circ->n_conn == orconn) {
    if(item->n_cell_ewma.heap_index > -1)
      remove_cell_ewma_from_conn(scheduler, &(item->n_cell_ewma));
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(orcirc->p_conn == orconn);
    if(item->p_cell_ewma.heap_index > -1)
      remove_cell_ewma_from_conn(scheduler, &(item->p_cell_ewma));
  }

  assert_active_circuits_ok_paranoid(orconn);
}

static void scheduler_ewma_unlink_active_items(scheduler_ewma_t *scheduler) {
  tor_assert(scheduler);

  SMARTLIST_FOREACH(scheduler->active_circuit_pqueue, cell_ewma_t *, e,
                    e->heap_index = -1);
  smartlist_clear(scheduler->active_circuit_pqueue);
}

static void scheduler_ewma_assert_active_items(scheduler_ewma_t *scheduler) {
  tor_assert(scheduler);
  or_connection_t *orconn = scheduler->_base.orconn;
  scheduleritem_ewma_t* item = NULL;
  circuit_t *circ = NULL;
  int n = 0;

  SMARTLIST_FOREACH(scheduler->active_circuit_pqueue, cell_ewma_t *, e,
    tor_assert(e);
    item = e->item;
    tor_assert(item);
    circ = item->_base.circ;
    tor_assert(circ);

    if (orconn == circ->n_conn) {
      tor_assert(e == &(item->n_cell_ewma));
    } else {
      or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
      tor_assert(orconn == orcirc->p_conn);
      tor_assert(e == &(item->p_cell_ewma));
    }

    tor_assert(e->heap_index != -1);
    tor_assert(e == smartlist_get(scheduler->active_circuit_pqueue,
                                     e->heap_index));
    n++;
  );

  tor_assert(n == smartlist_len(scheduler->active_circuit_pqueue));
}

static int scheduler_ewma_is_active(scheduler_ewma_t *scheduler) {
  tor_assert(scheduler);
  return (smartlist_len(scheduler->active_circuit_pqueue) > 0) ? 1 : 0;
}

static void scheduler_ewma_configure_priority(scheduler_ewma_t *scheduler,
    scheduleritem_ewma_t *item, int is_prioritized, size_t ncells) {
  tor_assert(scheduler);
  tor_assert(item);

//  if(item->is_eligible || get_options()->LiraKeepEligibility) {
//    int old_num = item->num_prioritized_remaining;

    if(is_prioritized) {
      (item->num_prioritized_remaining) += ncells;
//      if(old_num == 0 && ncells > 0) {
//        /* going from un-prioritized to prioritized. check if the circuits
//         * are active, and if so, re-scale them so their ewma can be adjusted
//         * to the new priority level
//         *
//         * deactivate the item, scale, then reactivate
//         *
//         * WARNING! this only deactivates the circuit in one direction - the
//         * direction that the given scheduler is responsible for. the circuit
//         * in the other direction will still exist in its old spot in its
//         * scheduler's priority queue until its chosen to send the next cell.
//         * this means its priority in the other direction wont actually be
//         * updated properly until the next cell is scheduled.
//         */
//        scheduler_ewma_deactivate_item(scheduler, item);
//
//        or_connection_t *orconn = scheduler->_base.orconn;
//        circuit_t *circ = item->_base.circ;
//
//        if (circ->n_conn == orconn) {
//          scale_single_cell_ewma(&(item->n_cell_ewma),
//              scheduler->active_circuit_pqueue_last_recalibrated);
//        } else {
//          or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
//          tor_assert(orcirc->p_conn == orconn);
//          scale_single_cell_ewma(&(item->p_cell_ewma),
//              scheduler->active_circuit_pqueue_last_recalibrated);
//        }
//
//        scheduler_ewma_activate_item(scheduler, item);
//      }
//    } else {
//      item->is_eligible = 0;
//    }
  }
}

scheduler_ewma_t *scheduler_ewma_new(or_connection_t *orconn) {
  scheduler_ewma_t *scheduler = tor_malloc_zero(sizeof(scheduler_ewma_t));

  /* TODO: this could move to a scheduler_init() func since its common among
   * all schedulers. */
  scheduler->_base.orconn = orconn;
  scheduler->_base.type = SCHEDULER_TYPE_EWMA;

  scheduler->_base.free = (scheduler_free_func) scheduler_ewma_free;
  scheduler->_base.select_item =
    (scheduler_select_item_func) scheduler_ewma_select_item;
  scheduler->_base.cell_added =
    (scheduler_cell_added_callback_func) scheduler_ewma_cell_added_callback;
  scheduler->_base.cell_removed =
    (scheduler_cell_removed_callback_func) scheduler_ewma_cell_removed_callback;
  scheduler->_base.item_scheduled =
    (scheduler_item_scheduled_callback_func) scheduler_ewma_item_scheduled_callback;
  scheduler->_base.activate_item =
    (scheduler_activate_item_func) scheduler_ewma_activate_item;
  scheduler->_base.deactivate_item =
      (scheduler_deactivate_item_func) scheduler_ewma_deactivate_item;
  scheduler->_base.unlink_active_items =
      (scheduler_unlink_active_items_func) scheduler_ewma_unlink_active_items;
  scheduler->_base.assert_active_items =
      (scheduler_assert_active_items_func) scheduler_ewma_assert_active_items;
  scheduler->_base.is_active =
      (scheduler_is_active_func) scheduler_ewma_is_active;
  scheduler->_base.configure_priority =
      (scheduler_configure_priority_func) scheduler_ewma_configure_priority;

  scheduler->active_circuit_pqueue = smartlist_new();
  scheduler->active_circuit_pqueue_last_recalibrated = cell_ewma_get_tick();

  return scheduler;
}

static void scheduleritem_ewma_free(scheduleritem_ewma_t *item) {
  tor_assert(item);
  tor_free(item);
}

static int scheduleritem_ewma_is_active_outward(scheduleritem_ewma_t *item) {
  tor_assert(item);
  return item->n_cell_ewma.heap_index != -1;
}

static int scheduleritem_ewma_is_active_inward(scheduleritem_ewma_t *item) {
  tor_assert(item);
  return item->p_cell_ewma.heap_index != -1;
}

scheduleritem_ewma_t *scheduleritem_ewma_new(circuit_t *circ) {
  scheduleritem_ewma_t * item = tor_malloc_zero(sizeof(scheduleritem_ewma_t));

  item->_base.circ = circ;
  item->_base.type = SCHEDULER_TYPE_EWMA;

  item->_base.free = (scheduleritem_free_func) scheduleritem_ewma_free;
  item->_base.is_active_outward =
    (scheduleritem_is_active_outward_func) scheduleritem_ewma_is_active_outward;
  item->_base.is_active_inward =
    (scheduleritem_is_active_inward_func) scheduleritem_ewma_is_active_inward;

  /* Initialize the cell_ewma_t structure */
  item->n_cell_ewma.last_adjusted_tick = cell_ewma_get_tick();
  item->p_cell_ewma.last_adjusted_tick = cell_ewma_get_tick();

  /* Initialize the cell counts to 0 */
  item->n_cell_ewma.cell_count = 0.0;
  item->p_cell_ewma.cell_count = 0.0;

  /* It's not in any heap yet. */
  item->n_cell_ewma.heap_index = -1;
  item->p_cell_ewma.heap_index = -1;

  /* give a pointer back to the containing item */
  item->n_cell_ewma.item = item;
  item->p_cell_ewma.item = item;

  item->is_eligible = 1;

  return item;
}

