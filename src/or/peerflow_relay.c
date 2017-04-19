/*
 * peerflow_relay.c
 *
 *  Created on: Oct 15, 2014
 *      Author: rob
 */

#include "or.h"
#include "channel.h"
#include "config.h"
#include "directory.h"
#include "peerflow.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"

typedef struct peerflow_relay_state_s {
  digestmap_t* peer_reports;
  struct timeval prev_report_time;
  struct timeval next_report_time;
  unsigned int seed_state;
  uint32_t magic;
} peerflow_relay_state_t;

#define PEERFLOW_RELAY_MAGIC 0x6D1239E3u

static peerflow_relay_state_t* pfrs = NULL;

static void _peerflow_relay_check_init() {
  if(pfrs) {
    return;
  }

  pfrs = tor_malloc_zero(sizeof(struct peerflow_relay_state_s));
  pfrs->magic = PEERFLOW_RELAY_MAGIC;
  pfrs->peer_reports = digestmap_new();
  pfrs->seed_state = 1; // TODO generate strong seed

  return;
}

void peerflow_relay_check_free() {
  if(!pfrs) {
    return;
  }

  digestmap_free(pfrs->peer_reports, (void (*)(void *))peerflow_report_free);

  tor_assert(pfrs->magic == PEERFLOW_RELAY_MAGIC);
  pfrs->magic = 0;
  tor_free(pfrs);
  pfrs = NULL;
}

static peerflow_report_t* _peerflow_relay_get_report(const routerinfo_t* peer_ri) {
  peerflow_report_t* report = digestmap_get(pfrs->peer_reports, peer_ri->cache_info.identity_digest);
  if(!report) {
    /* create a new record */
    report = peerflow_report_new(peer_ri->cache_info.identity_digest);
    digestmap_set(pfrs->peer_reports, peer_ri->cache_info.identity_digest, report);
  }
  return report;
}

static int _peerflow_relay_should_report() {
  /* check sorted relay weights and see if ours is above the threshold */
  /* for now all relays report and the authority decides which ones to keep */
  return 1;
}

void peerflow_relay_check_report() {
  _peerflow_relay_check_init();
  tor_assert(pfrs->magic == PEERFLOW_RELAY_MAGIC);

  /* we only report periodically */
  struct timeval now;
  tor_gettimeofday_cached_monotonic(&now);
  if(tv_mdiff(&pfrs->next_report_time, &now) < 0) {
    return;
  }

  /* so now we will try to format a new report */
  if(!digestmap_isempty(pfrs->peer_reports) && _peerflow_relay_should_report()) {
    /* get the information of the reporting peer (this node) */
    const routerinfo_t* ri = router_get_my_routerinfo();
    char id_hex[HEX_DIGEST_LEN+1];
    memset(id_hex, 0, HEX_DIGEST_LEN+1);
    base16_encode(id_hex, HEX_DIGEST_LEN+1, ri->cache_info.identity_digest, DIGEST_LEN);

    /* add noise to our peer observations before sending to authority */
    double laplace_scale = get_options()->PeerFlowLaplaceScale;
    if(laplace_scale > 0.0f) {
      peerflow_reports_obfuscate(pfrs->peer_reports, &pfrs->seed_state, laplace_scale);
    }

    /* create a report header for the reporting peer */
    char* report_header = NULL;
    tor_asprintf(&report_header, "%s %s %lu %lu %lu %lu",
        id_hex, ri ? ri->nickname : "unknown",
        (unsigned long)pfrs->prev_report_time.tv_sec, // our last report
        (unsigned long)pfrs->next_report_time.tv_sec, // now
        (unsigned long)rep_hist_bandwidth_assess(), // current capacity estimate
        (unsigned long)digestmap_size(pfrs->peer_reports));

    /* get the complete message */
    char* report_msg = peerflow_reports_to_string(pfrs->peer_reports, report_header);

    /* send it to dir auths */
    log_notice(LD_ACCT, "uploading peerflow report: %s", report_msg);
    directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_PEERFLOW_BW,
                                 ROUTER_PURPOSE_GENERAL,
                                 V3_DIRINFO, report_msg, strlen(report_msg), 0);

    /* cleanup */
    tor_free(report_header);
    tor_free(report_msg);
    /* clear for next round */
    digestmap_free(pfrs->peer_reports, (void (*)(void *))peerflow_report_free);
    pfrs->peer_reports = digestmap_new();
  }

  /* update report interval */
  pfrs->prev_report_time.tv_sec = pfrs->next_report_time.tv_sec;
  pfrs->prev_report_time.tv_usec = pfrs->next_report_time.tv_usec;
  tor_gettimeofday_cached_monotonic(&pfrs->next_report_time);
  pfrs->next_report_time.tv_sec += (time_t)get_options()->PeerFlowReportPeriod;
}

static void _peerflow_relay_handle_cell(channel_t* chan, circuit_t* circ, int was_sent) {
  _peerflow_relay_check_init();
  tor_assert(pfrs->magic == PEERFLOW_RELAY_MAGIC);

  if(!chan || !circ) {
    return;
  }

  /* this is the peer that bytes are being sent to or received from */
  const routerinfo_t* target_ri = router_get_by_id_digest(chan->identity_digest);

  /* we only report on known relays */
  if(!target_ri || router_digest_is_me(target_ri->cache_info.identity_digest)) {
    return;
  }

  /* if bytes were sent to target, this is where they came from;
   * if bytes were received from target, this is where they go next. */
  const routerinfo_t* relay_ri = NULL;
  PeerFlowSide side = PFS_NONE;

  if (chan == circ->n_chan) {
    side = PFS_CLIENT;
    if(CIRCUIT_IS_ORCIRC(circ)) {
      or_circuit_t* or_circ = TO_OR_CIRCUIT(circ);
      relay_ri = or_circ->p_chan ? router_get_by_id_digest(or_circ->p_chan->identity_digest) : NULL;
    }
  } else {
    side = PFS_DESTINATION;
    relay_ri = circ->n_chan ? router_get_by_id_digest(circ->n_chan->identity_digest) : NULL;
  }

  /* now infer our position given the side */
  PeerFlowPosition pos = PFP_NONE;
  if(relay_ri) {
    /* both ends are known relays, we are a middle */
    pos = PFP_MIDDLE;
  } else {
    /* one end is not a relay, so we are an edge relay */
    if(side == PFS_CLIENT) {
      pos = PFP_GUARD;
    } else {
      pos = PFP_EXIT;
    }
  }

  tor_assert(pos != PFP_NONE && side != PFS_NONE);

  /* number of bytes transferred for just the cell */
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);
  size_t bytes_sent = was_sent ? cell_network_size : 0;
  size_t bytes_received = was_sent ? 0 : cell_network_size;

  /* get and update the report for the target */
  peerflow_report_t* report = _peerflow_relay_get_report(target_ri);
  peerflow_report_add_bytes(report, bytes_received, bytes_sent, pos, side);
}

void peerflow_relay_notify_cell_received(channel_t* chan, circuit_t* circ) {
  _peerflow_relay_handle_cell(chan, circ, 0);
}

void peerflow_relay_notify_cell_sent(channel_t* chan, circuit_t* circ) {
  _peerflow_relay_handle_cell(chan, circ, 1);
}

void peerflow_relay_notify_bytes_observed(connection_t *conn,
    size_t bytes_received, size_t bytes_sent) {
  _peerflow_relay_check_init();
  tor_assert(pfrs->magic == PEERFLOW_RELAY_MAGIC);

  /* this is the peer that bytes are being sent to or received from */
  const routerinfo_t* target_ri = NULL;
  if(conn->type == CONN_TYPE_OR) {
    target_ri = router_get_by_id_digest(TO_OR_CONN(conn)->identity_digest);
  } else if(conn->type == CONN_TYPE_DIR) {
    target_ri = router_get_by_id_digest(TO_DIR_CONN(conn)->identity_digest);
  }

  /* we only report on known relays */
  if(!target_ri || router_digest_is_me(target_ri->cache_info.identity_digest)) {
    return;
  }

  /* get and update the report for the target
   * here, raw bytes are entering/leaving the system,
   * which will be a double count of the other sides/positions
   * but will also include bytes not sent/received on circuits.
   */
  peerflow_report_t* report = _peerflow_relay_get_report(target_ri);
  peerflow_report_add_bytes(report, bytes_received, bytes_sent, PFP_NONE, PFS_NONE);
}
