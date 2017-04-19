/*
 * peerflow_auth.c
 *
 *  Created on: Oct 15, 2014
 *      Author: rob
 */

#include "or.h"
#include "config.h"
#include "networkstatus.h"
#include "peerflow.h"
#include "router.h"

typedef struct peerflow_auth_report_s {
  unsigned long start_time;
  unsigned long end_time;
  peerflow_report_t* observations;
  unsigned long peer_traffic_estimate;
  unsigned long peer_traffic_estimate_weighted;
  uint32_t magic;
} peerflow_auth_report_t;

typedef struct peerflow_auth_peer_s {
  /* this peer's reported capacity estimate */
  unsigned long capacity_estimate;
  /* this peer's positional weighted consensus bandwidth */
  int pos_probs_are_stale;
  double weighted_bw_guard;
  double g_prob;
  double weighted_bw_middle;
  double m_prob;
  double weighted_bw_exit;
  double e_prob;
  /* all reports from other peers about this peer */
  digestmap_t* peer_reports;
  /* this peer's voting weight */
  unsigned long voting_weight;
  uint32_t magic;
} peerflow_auth_peer_t;

typedef struct peerflow_auth_state_s {
  /* all peers that have reported or been reported on */
  digestmap_t* peers;
  uint32_t magic;
} peerflow_auth_state_t;

#define PEERFLOW_AUTH_REPORT_MAGIC 0x6DFA39AAu
#define PEERFLOW_AUTH_PEER_MAGIC 0x6DFA39BBu
#define PEERFLOW_AUTH_MAGIC 0x6DFA39CCu

#define MEASURING_RELAY_COMBINED_WEIGHT_THRESHOLD 0.90

static peerflow_auth_state_t* pfas = NULL;

static peerflow_auth_report_t* _peerflow_auth_report_new() {
  peerflow_auth_report_t* report = tor_malloc_zero(sizeof(struct peerflow_auth_report_s));
  report->magic = PEERFLOW_AUTH_REPORT_MAGIC;
  return report;
}

static void _peerflow_auth_report_free(peerflow_auth_report_t* report) {
  tor_assert(report->magic == PEERFLOW_AUTH_REPORT_MAGIC);
  if(report->observations) {
    peerflow_report_free(report->observations);
  }
  report->magic = 0;
  tor_free(report);
}

static peerflow_auth_peer_t* _peerflow_auth_peer_new() {
  peerflow_auth_peer_t* peer = tor_malloc_zero(sizeof(struct peerflow_auth_peer_s));
  peer->magic = PEERFLOW_AUTH_PEER_MAGIC;
  peer->peer_reports = digestmap_new();
  return peer;
}

static void _peerflow_auth_peer_free(peerflow_auth_peer_t* peer) {
  tor_assert(peer->magic == PEERFLOW_AUTH_PEER_MAGIC);
  digestmap_free(peer->peer_reports, (void (*)(void *))_peerflow_auth_report_free);
  peer->magic = 0;
  tor_free(peer);
}

static int _peerflow_auth_parse_and_store_report(const char *report_str, const char **msg_out) {
  char reporter_id_digest[DIGEST_LEN];
  memset(reporter_id_digest, 0, DIGEST_LEN);

  char* report_str_copy = tor_strdup(report_str);
  char* semicolon = strstr(report_str_copy, ";");

  char* report_header = report_str_copy;
  char* report_body = NULL;
  if(semicolon) {
    semicolon[0] = 0x0;
    report_body = &semicolon[1];
  }

  /* get the reporter's info from the report header */
  char* ptr = NULL;
  char* id_hex = strtok_r(report_header, " ", &ptr);
  if(!id_hex) {
    *msg_out = "id_hex not found";
    goto err400;
  }
  char* name = strtok_r(NULL, " ", &ptr);
  if(!name) {
    *msg_out = "name not found";
    goto err400;
  }
  char* prev_time_seconds_str = strtok_r(NULL, " ", &ptr);
  if(!prev_time_seconds_str) {
    *msg_out = "prev_time_seconds not found";
    goto err400;
  }
  char* next_time_seconds_str = strtok_r(NULL, " ", &ptr);
  if(!next_time_seconds_str) {
    *msg_out = "next_time_seconds not found";
    goto err400;
  }
  char* capacity_estimate_str = strtok_r(NULL, " ", &ptr);
  if(!capacity_estimate_str) {
    *msg_out = "capacity_estimate not found";
    goto err400;
  }
  char* num_reports_str = strtok_r(NULL, " ", &ptr);
  if(!num_reports_str) {
    *msg_out = "num_reports not found";
    goto err400;
  }

  base16_decode(reporter_id_digest, DIGEST_LEN, id_hex, strnlen(id_hex, HEX_DIGEST_LEN));
  unsigned long prev_time_seconds = strtoul(prev_time_seconds_str, NULL, 10);
  unsigned long next_time_seconds = strtoul(next_time_seconds_str, NULL, 10);
  unsigned long capacity_estimate = strtoul(capacity_estimate_str, NULL, 10);
  unsigned long num_reports = strtoul(num_reports_str, NULL, 10);

  log_info(LD_ACCT, "peerflow parsed reporter %s %s %lu %lu %lu %lu",
      id_hex, name, prev_time_seconds, next_time_seconds,
      capacity_estimate, num_reports);

  /* process and store the reporter info.
   * make sure we know about the peer who is reporting */
  peerflow_auth_peer_t* reporter = digestmap_get(pfas->peers, reporter_id_digest);
  if(!reporter) {
    reporter = _peerflow_auth_peer_new();
    digestmap_set(pfas->peers, reporter_id_digest, reporter);
  }
  /* refresh its estimate */
  reporter->capacity_estimate = capacity_estimate;

  if(num_reports <= 0 || !report_body) {
    goto done;
  }

  /* get a map of the reports in the report body */
  digestmap_t* reports = peerflow_reports_from_string(report_body);
  if(!reports) {
    *msg_out = "error parsing reports";
    goto err400;
  }

  /* now go through the list of reports they sent us */
  DIGESTMAP_FOREACH(reports, id_key, peerflow_report_t*, p_report) {
    /* make sure we know about the peer that is being reported on */
    peerflow_auth_peer_t* peer = digestmap_get(pfas->peers, id_key);
    if(!peer) {
      peer = _peerflow_auth_peer_new();
      digestmap_set(pfas->peers, id_key, peer);
    }

    /* make sure the peer being reported on has a report from the reporter */
    peerflow_auth_report_t* a_report = digestmap_get(peer->peer_reports, reporter_id_digest);
    if(!a_report) {
      a_report = _peerflow_auth_report_new();
      digestmap_set(peer->peer_reports, reporter_id_digest, a_report);
    }

    /* clear out old observations if they exist */
    if(a_report->observations) {
      peerflow_report_free(a_report->observations);
    }

    /* now refresh the traffic estimate using the new observations */
    a_report->start_time = prev_time_seconds;
    a_report->end_time = next_time_seconds;
    a_report->observations = p_report;
    a_report->peer_traffic_estimate = 0; // recomputed at consensus vote time
  } DIGESTMAP_FOREACH_END;

  /* cleanup */
  //digestmap_free(reports, (void (*)(void *))peerflow_report_free);
  digestmap_free(reports, NULL);

done:
  tor_free(report_str_copy);
  return 200;

err400:
  tor_free(report_str_copy);
  return 400;
}

static void _peerflow_auth_check_init() {
  if(pfas || !authdir_mode_v3(get_options())) {
    return;
  }

  pfas = tor_malloc_zero(sizeof(struct peerflow_auth_state_s));
  pfas->magic = PEERFLOW_AUTH_MAGIC;
  pfas->peers = digestmap_new();

  return;
}

void peerflow_auth_check_free() {
  if(!pfas) {
    return;
  }

  digestmap_free(pfas->peers, (void (*)(void *))_peerflow_auth_peer_free);

  tor_assert(pfas->magic == PEERFLOW_AUTH_MAGIC);
  pfas->magic = 0;
  tor_free(pfas);
  pfas = NULL;
}

int peerflow_auth_notify_report_received(const char *report_body, const char **msg_out, int *status_out) {
  tor_assert(msg_out && status_out);
  if(!report_body) {
    *msg_out = "no report body";
    *status_out = 400;
    return 0;
  } else if(!authdir_mode_v3(get_options())) {
    *status_out = 200;
    return 1;
  }

  _peerflow_auth_check_init();

  int code = _peerflow_auth_parse_and_store_report(report_body, msg_out);
  log_notice(LD_ACCT, "peerflow %s received report: %s",
      code == 200 ? "successfully" : "unsuccessfully", report_body);

  /* on success, set status to 200 and return 1 */
  *status_out = code;
  return code == 200 ? 1 : 0;
}

static int _peerflow_auth_compare_traffic_estimates(
    const peerflow_auth_report_t** a, const peerflow_auth_report_t** b) {
  /* use the voting-weighted estimate */
  unsigned long est_a = (*a)->peer_traffic_estimate_weighted;
  unsigned long est_b = (*b)->peer_traffic_estimate_weighted;
  if (est_a < est_b)
    return 1;
  else if (est_a == est_b)
    return 0;
  else
    return -1;
}

static unsigned long _peerflow_auth_peer_get_median_estimate(
    peerflow_auth_peer_t* peer, smartlist_t *routerstatuses) {
  if(!peer->peer_reports) {
    /* bootstrap with the hacked initial v3bw info */
    return peer->voting_weight;
  }

  /* go through list of peer_reports and compute median
   * only include reports for peers that show up in routerstatuses */
  smartlist_t* estimates = smartlist_new();

  DIGESTMAP_FOREACH(peer->peer_reports, id_key, peerflow_auth_report_t*, report) {
    /* include the reports of those peers in the list of requested statuses */
    vote_routerstatus_t *rs = smartlist_bsearch(routerstatuses, id_key,
                           compare_digest_to_vote_routerstatus_entry);
    if (rs) {
      /* this is a report we should consider */
      smartlist_add(estimates, report);
    }
  } DIGESTMAP_FOREACH_END;

  peerflow_auth_report_t* report = NULL;
  int len = smartlist_len(estimates);

  if(len == 1) {
    report = smartlist_get(estimates, 0);
  } else if(len > 1) {
    smartlist_sort(estimates, (int (*)(const void**, const void**))_peerflow_auth_compare_traffic_estimates);
    report = smartlist_get(estimates, (int)(len-1/2));
  }

  smartlist_free(estimates);
  return report ? report->peer_traffic_estimate : 0;
}

static int32_t _peerflow_auth_get_weight(bandwidth_weight_rule_t rule, int is_guard, int is_exit) {
  if(rule == WEIGHT_FOR_GUARD) {
    if(is_guard && is_exit) {
      return networkstatus_get_bw_weight(NULL, "Wgd", -1);
    } else if(is_guard) {
      return networkstatus_get_bw_weight(NULL, "Wgg", -1);
    } else if(is_exit) {
      return 0;
    } else {
      return networkstatus_get_bw_weight(NULL, "Wgm", -1);
    }
  } else if(rule == WEIGHT_FOR_MID) {
    if(is_guard && is_exit) {
      return networkstatus_get_bw_weight(NULL, "Wmd", -1);
    } else if(is_guard) {
      return networkstatus_get_bw_weight(NULL, "Wmg", -1);
    } else if(is_exit) {
      return networkstatus_get_bw_weight(NULL, "Wme", -1);
    } else {
      return networkstatus_get_bw_weight(NULL, "Wmm", -1);
    }
  } else if(rule == WEIGHT_FOR_EXIT) {
    if(is_guard && is_exit) {
      return networkstatus_get_bw_weight(NULL, "Wed", -1);
    } else if(is_guard) {
      return networkstatus_get_bw_weight(NULL, "Weg", -1);
    } else if(is_exit) {
      return networkstatus_get_bw_weight(NULL, "Wee", -1);
    } else {
      return networkstatus_get_bw_weight(NULL, "Wem", -1);
    }
  }
  return 0;
}

static int _peerflow_auth_is_guard(const routerstatus_t* rs) {
  return rs->is_flagged_running && rs->is_valid && rs->is_possible_guard;
}

static int _peerflow_auth_is_exit(const routerstatus_t* rs) {
  return rs->is_flagged_running && rs->is_valid && rs->is_exit && !rs->is_bad_exit
      && rs->is_fast && rs->is_stable;
}

static int _peerflow_auth_is_middle(const routerstatus_t* rs) {
  return rs->is_flagged_running;
}

static void _peerflow_auth_compute_traffic_estimates(smartlist_t *routerstatuses) {
  int total_weighted_bw_g = 0, total_weighted_bw_m = 0, total_weighted_bw_e = 0;

  /* zero all existing peer weights peerflow knows about */
  DIGESTMAP_FOREACH(pfas->peers, id_key, peerflow_auth_peer_t*, peer) {
    if(peer) {
      peer->weighted_bw_guard = 0;
      peer->weighted_bw_middle = 0;
      peer->weighted_bw_exit = 0;
      peer->pos_probs_are_stale = 1;
    }
  } DIGESTMAP_FOREACH_END;

  /* recompute new weights for peers in new consensus using bw values from most recent consensus.
   * used to weight their observations of other peers during the last measurement period.
   * FIXME should these weights be averaged over all consensi in the measurement period? */
  SMARTLIST_FOREACH(routerstatuses, vote_routerstatus_t *, vrs, {
    routerstatus_t* pending_rs = &vrs->status;
    const routerstatus_t* latest_rs = router_get_consensus_status_by_descriptor_digest(NULL, pending_rs->descriptor_digest);

    if (!latest_rs) {
      /* we have a relay that is in the vote for the next consensus, but
       * could not be found in the latest consensus */
      continue;
    }
    peerflow_auth_peer_t* peer = digestmap_get(pfas->peers, latest_rs->identity_digest);

    int is_guard = _peerflow_auth_is_guard(latest_rs);
    int is_middle = _peerflow_auth_is_middle(latest_rs);
    int is_exit = _peerflow_auth_is_exit(latest_rs);

    if(is_guard) {
      int weighted_bw_g = (int) latest_rs->bandwidth_kb *
          _peerflow_auth_get_weight(WEIGHT_FOR_GUARD, is_guard, is_exit);
      total_weighted_bw_g += weighted_bw_g;
      if(peer) peer->weighted_bw_guard = weighted_bw_g;
    }
    if(is_middle) {
      int weighted_bw_m = (int) latest_rs->bandwidth_kb *
          _peerflow_auth_get_weight(WEIGHT_FOR_MID, is_guard, is_exit);
      total_weighted_bw_m += weighted_bw_m;
      if(peer) peer->weighted_bw_middle = weighted_bw_m;
    }
    if(is_exit) {
      int weighted_bw_e = (int) latest_rs->bandwidth_kb *
          _peerflow_auth_get_weight(WEIGHT_FOR_EXIT, is_guard, is_exit);
      total_weighted_bw_e += weighted_bw_e;
      if(peer) peer->weighted_bw_exit = weighted_bw_e;
    }
  });

  /* we must have gotten weights */
  tor_assert(total_weighted_bw_g > 0);
  tor_assert(total_weighted_bw_m > 0);
  tor_assert(total_weighted_bw_e > 0);

  /* compute all traffic estimates with new weights */
  SMARTLIST_FOREACH(routerstatuses, vote_routerstatus_t *, vrs, {
    routerstatus_t* pending_rs = &vrs->status;
    peerflow_auth_peer_t* peer = digestmap_get(pfas->peers, pending_rs->identity_digest);
    if(!peer || !peer->peer_reports) continue; // TODO what to do if a peer has not reports yet

    /* now go through the list of all reports about peer */
    DIGESTMAP_FOREACH(peer->peer_reports, id_key, peerflow_auth_report_t*, a_report) {
      /* get the reporting node */
      peerflow_auth_peer_t* reporter = digestmap_get(pfas->peers, id_key);
      tor_assert(reporter);

      /* update positional weights once per reporter */
      if(reporter->pos_probs_are_stale) {
        peer->g_prob = ((double)peer->weighted_bw_guard) / ((double)total_weighted_bw_g);
        peer->m_prob = ((double)peer->weighted_bw_middle) / ((double)total_weighted_bw_m);
        peer->e_prob = ((double)peer->weighted_bw_exit) / ((double)total_weighted_bw_e);
        peer->pos_probs_are_stale = 0;
        log_debug(LD_ACCT, "peerflow updated position probabilities for reporter %s: guard=%f middle=%f exit=%f",
            pending_rs->nickname, peer->g_prob, peer->m_prob, peer->e_prob);
      }

      /* now infer traffic estimate based on observations and weights */
      unsigned long bytes = peerflow_report_get_traffic_estimate(a_report->observations,
          reporter->g_prob, reporter->m_prob, reporter->e_prob);
      unsigned long interval =  (a_report->end_time - a_report->start_time);
      a_report->peer_traffic_estimate = (unsigned long) (interval > 0 ? bytes / interval : 0);

      unsigned long voting_weight = peer->voting_weight ? peer->voting_weight : 1;
      a_report->peer_traffic_estimate_weighted = a_report->peer_traffic_estimate * voting_weight;

      const routerstatus_t* reporter_rs = router_get_consensus_status_by_id(id_key);
      log_debug(LD_ACCT, "peerflow bandwidth of %s reported by %s: "
          "voting-weighted estimate %lu from estimate %lu and voting weight %lu",
          pending_rs->nickname, reporter_rs ? reporter_rs->nickname : "unknown",
          a_report->peer_traffic_estimate_weighted, a_report->peer_traffic_estimate, voting_weight);
    } DIGESTMAP_FOREACH_END;
  });
}

void peerflow_auth_process_measurements_for_consensus(smartlist_t *routerstatuses) {
  if(!routerstatuses) {
    return;
  }
  //  const routerinfo_t* ri_reporter = router_get_by_id_digest(reporter_id_digest);
  //  const routerstatus_t* rs_reporter = router_get_consensus_status_by_id(reporter_id_digest);

  /* make sure the authority has been initialized */
  _peerflow_auth_check_init();

  /* get the voting weight of this peer.
   * XXX this is a hack to use the weight from the first v3bw file as voting weight in
   * shadow but will have to change in production. */
  SMARTLIST_FOREACH(routerstatuses, vote_routerstatus_t *, vrs, {
      peerflow_auth_peer_t* peer = digestmap_get(pfas->peers, vrs->status.identity_digest);
      if(peer && !peer->voting_weight) {
        peer->voting_weight = vrs->measured_bw_kb;
      }
  });

  /* update our current estimates of traffic for all peers */
  _peerflow_auth_compute_traffic_estimates(routerstatuses);

  SMARTLIST_FOREACH(routerstatuses, vote_routerstatus_t *, vrs, {
      peerflow_auth_peer_t* peer = digestmap_get(pfas->peers, vrs->status.identity_digest);
      if(peer) {
        /* now compute the peer's median traffic estimate */
        unsigned long traffic_est = _peerflow_auth_peer_get_median_estimate(peer, routerstatuses);
        unsigned long capacity_est = peer->capacity_estimate;

        unsigned long consensus_est = capacity_est; // FIXME how does capacity affect this?

        /* update the measured bandwidth info for the consensus vote.
         * !NOTE: these values will only show up in the consensus if
         * 3 or more votes from all dirauths have measured values
         * for this relay. if your network has less than 3 dirauths,
         * these values will be ignored in favor of advertised bw. */
        vrs->has_measured_bw = 1;
        vrs->measured_bw_kb = (uint32_t)consensus_est;

        char name[HEX_DIGEST_LEN+1];
        base16_encode(name, HEX_DIGEST_LEN+1, vrs->status.identity_digest, DIGEST_LEN);
        log_debug(LD_ACCT, "peerflow set bandwidth to %lu for node %s %s", consensus_est, vrs->status.nickname, name);
      }
  });
}
