/**
 * This is a quick attempt at modularizing the Tor scheduling infrastructure.
 * Designed/written on 2012-03-18 by Rob Jansen <jansen@cs.umn.edu>
 */

#ifndef SCHEDULER_H_
#define SCHEDULER_H_

#include "or.h"

enum scheduler_type {
  SCHEDULER_TYPE_NONE=0, SCHEDULER_TYPE_RR=1, SCHEDULER_TYPE_EWMA=2,
  SCHEDULER_TYPE_PDD=3,
};

/** scheduler base class */
typedef struct scheduler_s scheduler_t;

/** scheduler item base class */
typedef struct scheduleritem_s scheduleritem_t;

/** functions for a scheduler module */
typedef void (*scheduler_free_func)(scheduler_t *scheduler);
typedef scheduleritem_t* (*scheduler_select_item_func)(scheduler_t *scheduler);
typedef void (*scheduler_cell_added_callback_func)(scheduler_t *scheduler,
    scheduleritem_t* item);
typedef int (*scheduler_cell_removed_callback_func)(scheduler_t *scheduler,
    scheduleritem_t* item);
typedef void (*scheduler_item_scheduled_callback_func)(scheduler_t *scheduler,
    scheduleritem_t* item);
typedef void (*scheduler_activate_item_func)(scheduler_t *scheduler,
    scheduleritem_t *item);
typedef void (*scheduler_deactivate_item_func)(scheduler_t *scheduler,
    scheduleritem_t *item);
typedef void (*scheduler_unlink_active_items_func)(scheduler_t *scheduler);
typedef void (*scheduler_assert_active_items_func)(scheduler_t *scheduler);
typedef int (*scheduler_is_active_func)(scheduler_t *scheduler);
typedef void (*scheduler_configure_priority_func)(scheduler_t *scheduler,
    scheduleritem_t *item, int is_prioritized, size_t ncells);

/**
 * Contains per-scheduler info needed to make circuit scheduling decisions.
 * This is the base class for all scheduler states, so the struct has to be
 * visible but should only be accessed through the scheduler_state_* functions.
 */
struct scheduler_s {
  enum scheduler_type type;

  or_connection_t *orconn;

  scheduler_free_func free;
  scheduler_select_item_func select_item;
  scheduler_cell_added_callback_func cell_added;
  scheduler_cell_removed_callback_func cell_removed;
  scheduler_item_scheduled_callback_func item_scheduled;
  scheduler_activate_item_func activate_item;
  scheduler_deactivate_item_func deactivate_item;
  scheduler_unlink_active_items_func unlink_active_items;
  scheduler_assert_active_items_func assert_active_items;
  scheduler_is_active_func is_active;
  scheduler_configure_priority_func configure_priority;
};

/* create a new scheduler of the given type.
 * returns a pointer to a subtype of scheduler_t, which can be stored
 * in the baseclass type scheduler_t*. */
#define scheduler_new(schedulerp, type, orconn) { \
  switch (type) { \
    case SCHEDULER_TYPE_EWMA: { \
      schedulerp = (scheduler_t*) scheduler_ewma_new(orconn); \
      break; \
    } \
    case SCHEDULER_TYPE_PDD: { \
      schedulerp = (scheduler_t*) scheduler_pdd_new(orconn); \
      break; \
    } \
    default: \
    case SCHEDULER_TYPE_RR: { \
    	schedulerp = (scheduler_t*) scheduler_rr_new(orconn); \
      break; \
    } \
  } \
}

/** the scheduler interface */
#define scheduler_free(sched) (sched->free(sched))
#define scheduler_select_item(sched) (sched->select_item(sched))
#define scheduler_cell_added_callback(sched, item) (sched->cell_added(sched, item))
#define scheduler_cell_removed_callback(sched, item) (sched->cell_removed(sched, item))
#define scheduler_item_scheduled_callback(sched, item) (sched->item_scheduled(sched, item))
#define scheduler_activate_item(sched, item) (sched->activate_item(sched, item))
#define scheduler_deactivate_item(sched, item) (sched->deactivate_item(sched, item))
#define scheduler_unlink_active_items(sched) (sched->unlink_active_items(sched))
#define scheduler_assert_active_items(sched) (sched->assert_active_items(sched))
#define scheduler_is_active(sched) (sched->is_active(sched))
#define scheduler_configure_priority(sched, item, is_p, n) (sched->configure_priority(sched, item, is_p, n))

#ifdef ACTIVE_CIRCUITS_PARANOIA
#define assert_active_circuits_ok_paranoid(conn) \
    scheduler_assert_active_items(conn->scheduler)
#else
#define assert_active_circuits_ok_paranoid(conn)
#endif

/** functions for a scheduler item module */
typedef void (*scheduleritem_free_func)(scheduleritem_t *item);
typedef int (*scheduleritem_is_active_outward_func)(scheduleritem_t *item);
typedef int (*scheduleritem_is_active_inward_func)(scheduleritem_t *item);

/**
 * Contains per-circuit info needed to make circuit scheduling decisions.
 * This is the base class for all scheduler states, so the struct has to be
 * visible but should only be accessed through the scheduler_* functions.
 */
struct scheduleritem_s {
  enum scheduler_type type;

  circuit_t *circ;

  scheduleritem_free_func free;
  scheduleritem_is_active_outward_func is_active_outward;
  scheduleritem_is_active_inward_func is_active_inward;
};

/* create a new scheduleritem of the given type.
 * returns a pointer to a subtype of scheduleritem_t, which can be stored
 * in the baseclass type scheduleritem_t*. */
#define scheduleritem_new(itemp, type, circ) { \
  switch (type) { \
    case SCHEDULER_TYPE_EWMA: { \
      itemp = (scheduleritem_t*)scheduleritem_ewma_new(circ); \
      break; \
    } \
    case SCHEDULER_TYPE_PDD: { \
      itemp = (scheduleritem_t*)scheduleritem_pdd_new(circ); \
      break; \
    } \
    default: \
    case SCHEDULER_TYPE_RR: { \
    	itemp = (scheduleritem_t*)scheduleritem_rr_new(circ); \
      break; \
    } \
  } \
}

/** the scheduleritem interface */
#define scheduleritem_free(item) (item->free(item))
#define scheduleritem_is_active_outward(item) (item->is_active_outward(item))
#define scheduleritem_is_active_inward(item) (item->is_active_inward(item))

/** public definition for the opaque scheduler_rr struct, which should only
 * be accessed through the scheduler_rr_* functions */
typedef struct scheduler_rr_s scheduler_rr_t;
typedef struct scheduleritem_rr_s scheduleritem_rr_t;
scheduler_rr_t *scheduler_rr_new(or_connection_t *orconn);
scheduleritem_rr_t *scheduleritem_rr_new(circuit_t *circ);

/** public definition for the opaque scheduler_ewma struct, which should only
 * be accessed through the scheduler_ewma_* functions */
typedef struct scheduler_ewma_s scheduler_ewma_t;
typedef struct scheduleritem_ewma_s scheduleritem_ewma_t;
scheduler_ewma_t *scheduler_ewma_new(or_connection_t *orconn);
scheduleritem_ewma_t *scheduleritem_ewma_new(circuit_t *circ);
void cell_ewma_set_scale_factor(const or_options_t *options,
                           const networkstatus_t *consensus);

/** public definition for the opaque scheduler_pdd struct, which should only
 * be accessed through the scheduler_pdd_* functions */
typedef struct scheduler_pdd_s scheduler_pdd_t;
typedef struct scheduleritem_pdd_s scheduleritem_pdd_t;
scheduler_pdd_t *scheduler_pdd_new(or_connection_t *orconn);
scheduleritem_pdd_t *scheduleritem_pdd_new(circuit_t *circ);

#endif /* SCHEDULER_H_ */
