/**
 * This is a quick attempt at modularizing the Tor scheduling infrastructure.
 * Code adapted from relay.c on 2012-03-18 by Rob Jansen <jansen@cs.umn.edu>
 */

#include "or.h"
#include "scheduler.h"

/**
 * State specific to the round-robin scheduler
 * This extends scheduler_s
 */
struct scheduler_rr_s {
  scheduler_t _base;

  /** Double-linked ring of circuits with queued cells waiting for room to
   * free up on this connection's outbuf.  Every time we pull cells from a
   * circuit, we advance this pointer to the next circuit in the ring. */
  scheduleritem_rr_t *active_circuits;
};

struct scheduleritem_rr_s {
  scheduleritem_t _base;

  /** Next circuit in the doubly-linked ring of circuits waiting to add
   * cells to n_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  scheduleritem_rr_t *next_active_on_n_conn;

  /** Previous circuit in the doubly-linked ring of circuits waiting to add
   * cells to n_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  scheduleritem_rr_t *prev_active_on_n_conn;

  /** Next circuit in the doubly-linked ring of circuits waiting to add
   * cells to p_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  scheduleritem_rr_t *next_active_on_p_conn;

  /** Previous circuit in the doubly-linked ring of circuits waiting to add
   * cells to p_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  scheduleritem_rr_t *prev_active_on_p_conn;
};

/** Return a pointer to the "next_active_on_{n,p}_conn" pointer of <b>circ</b>,
 * depending on whether <b>conn</b> matches n_conn or p_conn. */
static INLINE scheduleritem_rr_t **
next_circ_on_conn_p(scheduler_rr_t *scheduler, scheduleritem_rr_t* item)
{
  tor_assert(scheduler);
  tor_assert(scheduler->_base.orconn);
  tor_assert(item);
  tor_assert(item->_base.circ);

  if (scheduler->_base.orconn == item->_base.circ->n_conn) {
    return &item->next_active_on_n_conn;
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(item->_base.circ);
    tor_assert(scheduler->_base.orconn == orcirc->p_conn);
    return &item->next_active_on_p_conn;
  }
}

/** Return a pointer to the "prev_active_on_{n,p}_conn" pointer of <b>circ</b>,
 * depending on whether <b>conn</b> matches n_conn or p_conn. */
static INLINE scheduleritem_rr_t **
prev_circ_on_conn_p(scheduler_rr_t *scheduler, scheduleritem_rr_t* item)
{
  tor_assert(scheduler);
  tor_assert(scheduler->_base.orconn);
  tor_assert(item);
  tor_assert(item->_base.circ);

  if (scheduler->_base.orconn == item->_base.circ->n_conn) {
    return &item->prev_active_on_n_conn;
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(item->_base.circ);
    tor_assert(scheduler->_base.orconn == orcirc->p_conn);
    return &item->prev_active_on_p_conn;
  }
}

static void scheduler_rr_free(scheduler_rr_t *scheduler) {
  tor_assert(scheduler);
  tor_free(scheduler);
}

static scheduleritem_rr_t* scheduler_rr_select_item(scheduler_rr_t *scheduler) {
  tor_assert(scheduler);
  return scheduler->active_circuits;
}

static void scheduler_rr_cell_added_callback(scheduler_rr_t *scheduler,
    scheduleritem_rr_t* item) {
  /* do nothing */
  return;
}

static int scheduler_rr_cell_removed_callback(scheduler_rr_t *scheduler,
    scheduleritem_rr_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  if (item != scheduler->active_circuits) {
    /* If this happens, the current circuit just got made inactive by
     * a call in connection_write_to_buf().  That's nothing to worry about:
     * circuit_make_inactive_on_conn() already advanced conn->active_circuits
     * for us.
     */
    return 1;
  }
  return 0;
}

static void scheduler_rr_item_scheduled_callback(scheduler_rr_t *scheduler,
    scheduleritem_rr_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  tor_assert(*next_circ_on_conn_p(scheduler, item));

  /* we just scheduled one circuit. we are doing round-robin, so set the
   * active circuit pointer to the next circuit in the ring.
   */
  scheduler->active_circuits = *next_circ_on_conn_p(scheduler, item);
}

static void scheduler_rr_activate_item(scheduler_rr_t *scheduler,
    scheduleritem_rr_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  scheduleritem_rr_t **nextp = next_circ_on_conn_p(scheduler, item);
  scheduleritem_rr_t **prevp = prev_circ_on_conn_p(scheduler, item);

  if (*nextp && *prevp) {
    /* Already active. */
    return;
  }

  assert_active_circuits_ok_paranoid(scheduler->_base.orconn);

  if (! scheduler->active_circuits) {
    scheduler->active_circuits = item;
    *prevp = *nextp = item;
  } else {
    scheduleritem_rr_t *head = scheduler->active_circuits;
    scheduleritem_rr_t *old_tail = *prev_circ_on_conn_p(scheduler, head);
    *next_circ_on_conn_p(scheduler, old_tail) = item;
    *nextp = head;
    *prev_circ_on_conn_p(scheduler, head) = item;
    *prevp = old_tail;
  }

  assert_active_circuits_ok_paranoid(scheduler->_base.orconn);
}

static void scheduler_rr_deactivate_item(scheduler_rr_t *scheduler,
    scheduleritem_rr_t* item) {
  tor_assert(scheduler);
  tor_assert(item);

  scheduleritem_rr_t **nextp = next_circ_on_conn_p(scheduler, item);
  scheduleritem_rr_t **prevp = prev_circ_on_conn_p(scheduler, item);
  scheduleritem_rr_t *next = *nextp, *prev = *prevp;

  if (!next && !prev) {
    /* Already inactive. */
    return;
  }

  assert_active_circuits_ok_paranoid(scheduler->_base.orconn);

  tor_assert(next && prev);
  tor_assert(*prev_circ_on_conn_p(scheduler, next) == item);
  tor_assert(*next_circ_on_conn_p(scheduler, prev) == item);

  if (next == item) {
    scheduler->active_circuits = NULL;
  } else {
    *prev_circ_on_conn_p(scheduler, next) = prev;
    *next_circ_on_conn_p(scheduler, prev) = next;
    if (scheduler->active_circuits == item)
      scheduler->active_circuits = next;
  }
  *prevp = *nextp = NULL;

  assert_active_circuits_ok_paranoid(scheduler->_base.orconn);
}

static void scheduler_rr_unlink_active_items(scheduler_rr_t *scheduler) {
  tor_assert(scheduler);

  scheduleritem_rr_t *head = scheduler->active_circuits;
  scheduleritem_rr_t *cur = head;
  if (! head)
    return;
  do {
    scheduleritem_rr_t *next = *next_circ_on_conn_p(scheduler, cur);
    *prev_circ_on_conn_p(scheduler, cur) = NULL;
    *next_circ_on_conn_p(scheduler, cur) = NULL;
    cur = next;
  } while (cur != head);
  scheduler->active_circuits = NULL;
}

static void scheduler_rr_assert_active_items(scheduler_rr_t *scheduler) {
  tor_assert(scheduler);

  scheduleritem_rr_t *head = scheduler->active_circuits;
  scheduleritem_rr_t *cur = head;
  int n = 0;
  if (! head)
    return;
  do {
    scheduleritem_rr_t *next = *next_circ_on_conn_p(scheduler, cur);
    scheduleritem_rr_t *prev = *prev_circ_on_conn_p(scheduler, cur);
    tor_assert(next);
    tor_assert(prev);
    tor_assert(*next_circ_on_conn_p(scheduler, prev) == cur);
    tor_assert(*prev_circ_on_conn_p(scheduler, next) == cur);
    n++;
    cur = next;
  } while (cur != head);
}

static int scheduler_rr_is_active(scheduler_rr_t *scheduler) {
  tor_assert(scheduler);
  return scheduler->active_circuits != NULL;
}

static void scheduler_rr_configure_priority(scheduler_rr_t *scheduler,
    scheduleritem_rr_t *item, int is_prioritized, size_t ncells) {
  return;
}

scheduler_rr_t *scheduler_rr_new(or_connection_t *orconn) {
  scheduler_rr_t *scheduler = tor_malloc_zero(sizeof(scheduler_rr_t));

  /* TODO: this could move to a scheduler_init() func since its common among
   * all schedulers. */
  scheduler->_base.orconn = orconn;
  scheduler->_base.type = SCHEDULER_TYPE_RR;

  scheduler->_base.free = (scheduler_free_func) scheduler_rr_free;
  scheduler->_base.select_item =
    (scheduler_select_item_func) scheduler_rr_select_item;
  scheduler->_base.cell_added =
    (scheduler_cell_added_callback_func) scheduler_rr_cell_added_callback;
  scheduler->_base.cell_removed =
    (scheduler_cell_removed_callback_func) scheduler_rr_cell_removed_callback;
  scheduler->_base.item_scheduled =
    (scheduler_item_scheduled_callback_func) scheduler_rr_item_scheduled_callback;
  scheduler->_base.activate_item =
    (scheduler_activate_item_func) scheduler_rr_activate_item;
  scheduler->_base.deactivate_item =
      (scheduler_deactivate_item_func) scheduler_rr_deactivate_item;
  scheduler->_base.unlink_active_items =
      (scheduler_unlink_active_items_func) scheduler_rr_unlink_active_items;
  scheduler->_base.assert_active_items =
      (scheduler_assert_active_items_func) scheduler_rr_assert_active_items;
  scheduler->_base.is_active =
      (scheduler_is_active_func) scheduler_rr_is_active;
  scheduler->_base.is_active =
      (scheduler_configure_priority_func) scheduler_rr_configure_priority;

  return scheduler;
}

static void scheduleritem_rr_free(scheduleritem_rr_t *item) {
  tor_assert(item);
  tor_free(item);
}

static int scheduleritem_rr_is_active_outward(scheduleritem_rr_t *item) {
  tor_assert(item);
  return item->next_active_on_n_conn != NULL;
}

static int scheduleritem_rr_is_active_inward(scheduleritem_rr_t *item) {
  tor_assert(item);
  return item->next_active_on_p_conn != NULL;
}

scheduleritem_rr_t *scheduleritem_rr_new(circuit_t *circ) {
  scheduleritem_rr_t * item = tor_malloc_zero(sizeof(scheduleritem_rr_t));

  item->_base.circ = circ;
  item->_base.type = SCHEDULER_TYPE_RR;

  item->_base.free = (scheduleritem_free_func) scheduleritem_rr_free;
  item->_base.is_active_outward =
    (scheduleritem_is_active_outward_func) scheduleritem_rr_is_active_outward;
  item->_base.is_active_inward =
    (scheduleritem_is_active_inward_func) scheduleritem_rr_is_active_inward;

  return item;
}
