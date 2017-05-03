/*
 * trust.c
 *
 *  Created on: Apr 28, 2014
 *      Author: rob
 */

#include <glib.h>
#include "or.h"
#include "address.h"
#include "trust.h"
#include "config.h"
#include "nodelist.h"
#include "circuitbuild.h"
#include "circuituse.h"
#include "container.h"
#include "routerlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct trust_info_s {
  trustdb_t* tdb;
  smartlist_t* my_guards;
  double guard_scores_max;

  in_addr_t guard_netip_temp;
  unsigned int dest_asn_temp;
} trust_info_t;

static trust_info_t* trusti = NULL;

/* shadow should intercept this function and return the ASN */
int trust_get_asn(in_addr_t ip, int* asnout) {
  assert(0 && "trust_get_asn should be intercepted and handled by shadow");
	return 0;
}

int trust_get_cc(in_addr_t ip, char* ccout) {
  assert(0 && "trust_get_cc should be intercepted and handled by shadow");
  return 0;
}

void trust_init() {
  const or_options_t* oro = get_options();
  tor_assert(oro && oro->SelectPathsWithTrust);
  trusti = g_new(trust_info_t, 1);

  if(oro->TrustPolicyCountry) {
    tor_assert(oro->TrustCountriesFile);
  }

  int asn = 0;
  int success = trust_get_asn(INADDR_NONE, &asn);
  unsigned int my_asn = (unsigned int)asn;
  tor_assert(my_asn && success);

  gchar myccbuf[32];
  memset(myccbuf, 0, 32);
  success = trust_get_cc(INADDR_NONE, myccbuf);
  tor_assert(success);
  gchar* mycc = g_ascii_strdown(myccbuf, -1);

  gchar myname[256];
  memset(myname, 0, 256);
  int retval = gethostname(myname, 256);
  tor_assert(retval == 0);

  in_addr_t mynetip = INADDR_NONE;
  struct addrinfo* info;
  if(getaddrinfo(myname, NULL, NULL, &info) != -1) {
    mynetip = ((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr;
  }
  tor_assert(mynetip != INADDR_NONE);

  trusti->my_guards = smartlist_new();

  trusti->tdb = trustdb_new(mynetip, my_asn, mycc, oro->TrustClientsFile,
      oro->TrustGuardsFile, oro->TrustExitsFile,
      oro->TrustServersFile, oro->TrustScoresFile,
      oro->TrustAdvsInFile, oro->TrustAdvsOutFile, oro->TrustCountriesFile);

  log_notice(LD_GENERAL, "initialized trust module with ASN=%i", my_asn);
}

void trust_free() {
  if(trusti) {
    if(trusti->my_guards) {
      smartlist_free(trusti->my_guards);
    }
    if(trusti->tdb) {
      trustdb_free(trusti->tdb);
    }
  }
}

static gchar* trust_get_circ_addr_string(uint32_t entryAddr, uint32_t middleAddr, uint32_t exitAddr) {
  char entryAddrStr[20];
  if(entryAddr > 0) {
	struct in_addr in;
	in.s_addr = htonl(entryAddr);
	tor_inet_ntoa(&in, entryAddrStr, INET_NTOA_BUF_LEN);
  } else {
	  memset(entryAddrStr, 0, 20);
	  snprintf(entryAddrStr, 20, "unknown");
  }

  char middleAddrStr[20];
  if(middleAddr > 0) {
	struct in_addr in;
	in.s_addr = htonl(middleAddr);
	tor_inet_ntoa(&in, middleAddrStr, INET_NTOA_BUF_LEN);
  } else {
	  memset(middleAddrStr, 0, 20);
	  snprintf(middleAddrStr, 20, "unknown");
  }

  char exitAddrStr[20];
  if(exitAddr > 0) {
	struct in_addr in;
	in.s_addr = htonl(exitAddr);
	tor_inet_ntoa(&in, exitAddrStr, INET_NTOA_BUF_LEN);
  } else {
	  memset(exitAddrStr, 0, 20);
	  snprintf(exitAddrStr, 20, "unknown");
  }

  GString* s = g_string_new(NULL);
  g_string_append_printf(s, "%s->%s->%s", entryAddrStr, middleAddrStr, exitAddrStr);
  return g_string_free(s, FALSE);
}

static unsigned int _trust_get_dest_asn(const entry_connection_t *conn) {
  struct in_addr dest_inaddr;
  tor_assert(1 == inet_pton(AF_INET, conn->original_dest_address, &dest_inaddr));
  in_addr_t dest_ip = dest_inaddr.s_addr;
  int dest_asn = 0;
  trust_get_asn(dest_ip, &dest_asn);
  tor_assert(dest_asn > 0);
  return (unsigned int)dest_asn;
}

static int _trust_node_has_info(const node_t* node) {
  if (node->ri == NULL && (node->rs == NULL || node->md == NULL))
    return 0;
  else
    return 1;
}

static void _trust_calculate_guard_scores(const smartlist_t* nodes) {
    int guard_count = 0;
    trusti->guard_scores_max = 0.0f;

    SMARTLIST_FOREACH(nodes, node_t *, node,
      if(node->is_possible_guard && node->is_fast && node->is_running && node->is_valid
          && _trust_node_has_info(node)) {
        guard_count++;
        double score = trustdb_get_guard_score(trusti->tdb, trusti->my_guards, node);
        if(score != -1.0f && score > trusti->guard_scores_max) {
          trusti->guard_scores_max = score;
        }
      }
    );

    log_info(LD_CIRC, "trust: from %i guards, max guard score is %f",
            guard_count, trusti->guard_scores_max);
}

static int _trust_compare_guard_scores(const void** a, const void** b) {
  const node_t* node_a = *a;
  double node_a_score = trustdb_get_guard_score(trusti->tdb, trusti->my_guards, node_a);

  const node_t* node_b = *b;
  double node_b_score = trustdb_get_guard_score(trusti->tdb, trusti->my_guards, node_b);

  if(node_a_score < node_b_score) {
    return -1; // the lowest score will come at the front of the list
  } else if(node_a_score == node_b_score) {
    return 0;
  } else {
    return 1; // the highest score will come at the back of the list
  }
}

static int _trust_compare_exit_scores(const void** a, const void** b) {
  const node_t* node_a = *a;
  in_addr_t node_a_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node_a));
  double node_a_score = trustdb_get_exit_score(trusti->tdb, trusti->guard_netip_temp, node_a_netip, trusti->dest_asn_temp);

  const node_t* node_b = *b;
  in_addr_t node_b_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node_b));
  double node_b_score = trustdb_get_exit_score(trusti->tdb, trusti->guard_netip_temp, node_b_netip, trusti->dest_asn_temp);

  if(node_a_score < node_b_score) {
    return -1; // the lowest score will come at the front of the list
  } else if(node_a_score == node_b_score) {
    return 0;
  } else {
    return 1; // the highest score will come at the back of the list
  }
}

static void _trust_add_guard(const node_t* guard) {
  tor_assert(guard);

  smartlist_add(trusti->my_guards, guard);

  log_notice(LD_CIRC, "trust: chosen_guard=%s n_guards=%i",
      guard->ri ? guard->ri->nickname : guard->rs ? guard->rs->nickname : "unknown",
       smartlist_len(trusti->my_guards));
}

static void _trust_choose_guards_trustone() {
  smartlist_t* nodes = nodelist_get_list();
  log_info(LD_CIRC, "trust: choosing guards, we have %i total nodes", smartlist_len(nodes));

  // recalculate in case we learned about new nodes
  _trust_calculate_guard_scores(nodes);

  smartlist_t* choices = smartlist_new();
  smartlist_t* allguards = smartlist_new();
  double bw_weight_total = 0.0f;
  double bw_weight_choices = 0.0f;

  SMARTLIST_FOREACH(nodes, node_t *, node,
    if(node->is_possible_guard && node->is_fast && node->is_running && node->is_valid
        && _trust_node_has_info(node)) {
      double guard_weight = (double)node->rs->bandwidth_kb;
      bw_weight_total += guard_weight;
      smartlist_add(allguards, node);
    }
  );

  int guard_count = smartlist_len(allguards);

  double bw_frac = get_options()->TrustMinBWWeightFractionGuard;
  if(bw_frac <= 0.0f) {
    bw_frac = get_options()->TrustMinBWWeightFraction;
  }

  double bw_required = bw_weight_total * bw_frac;
  smartlist_sort(allguards, _trust_compare_guard_scores);

  while(smartlist_len(allguards) > 0 && bw_weight_choices < bw_required) {
    node_t* node = smartlist_pop_last(allguards);
    double node_weight = (double)node->rs->bandwidth_kb;
    bw_weight_choices += node_weight;
    smartlist_add(choices, node);
  }

  log_notice(LD_CIRC, "trust: guard_scores_max=%f "
      "bw_total=%f bw_choices=%f bw_required=%f "
      "n_potential_guards=%i n_choices=%i",
       trusti->guard_scores_max,
       bw_weight_total, bw_weight_choices, bw_required,
       guard_count, smartlist_len(choices));

    while(smartlist_len(trusti->my_guards) < 3 && smartlist_len(choices) > 0) {
      const node_t* node = node_sl_choose_by_bandwidth(choices, WEIGHT_FOR_GUARD);
  //    in_addr_t node_ip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
      if(!smartlist_contains(trusti->my_guards, node)) {
        _trust_add_guard(node);
      }
      smartlist_remove(choices, node);
    }

    int n_guards = smartlist_len(trusti->my_guards);
    log_info(LD_CIRC, "trust: we have %i guards in pool%s", n_guards,
        n_guards >= 3 ? ", yay!" : n_guards < 1 ? ", circuits will fail without guards!!" : "");

    smartlist_free(choices);
    smartlist_free(allguards);
}

static void _trust_choose_guards_trustall() {
  smartlist_t* nodes = nodelist_get_list();
  log_info(LD_CIRC, "trust: choosing guards, we have %i total nodes", smartlist_len(nodes));

  // recalculate in case we learned about new nodes
  _trust_calculate_guard_scores(nodes);

  smartlist_t* choices = smartlist_new();
  smartlist_t* acceptable = smartlist_new();
  int guard_count = 0;
  double bw_weight_total = 0.0f;
  double bw_weight_safe = 0.0f;
  double bw_weight_acceptable = 0.0f;
  double bw_weight_choices = 0.0f;

  /* always add all 'safe' nodes, and then
   * add all 'acceptable' nodes until we reach our required bandwidth */

  double safe_uncomp_threshold = trusti->guard_scores_max * get_options()->TrustSafeGuardUncompThresh;
  double safe_comp_threshold = (1.0f - trusti->guard_scores_max) * get_options()->TrustSafeGuardCompThresh;
  double acceptable_uncomp_threshold = trusti->guard_scores_max * get_options()->TrustAcceptableGuardUncompThresh;
  double acceptable_comp_threshold = (1.0f - trusti->guard_scores_max) * get_options()->TrustAcceptableGuardCompThresh;

  //(score >= top_guard_score*uncomp_threshold) and
  //(1-score <= (1-top_guard_score)*comp_threshold)
  SMARTLIST_FOREACH(nodes, node_t *, node,
    if(node->is_possible_guard && node->is_fast && node->is_running && node->is_valid
        && _trust_node_has_info(node)) {
      guard_count++;
      double guard_weight = (double)node->rs->bandwidth_kb;

      bw_weight_total += guard_weight;

      double score = trustdb_get_guard_score(trusti->tdb, trusti->my_guards, node);
      if(score >= 0.0f) {
        if(score >= safe_uncomp_threshold && (1.0f - score) <= safe_comp_threshold) {
          smartlist_add(choices, node);
          bw_weight_safe += guard_weight;
          bw_weight_choices += guard_weight;
        } else if(score >= acceptable_uncomp_threshold && (1.0f - score) <= acceptable_comp_threshold) {
          smartlist_add(acceptable, node);
          bw_weight_acceptable += guard_weight;
        }
      }
    }
  );

  int n_safe_guards = smartlist_len(choices);
  int n_acceptable_guards = smartlist_len(acceptable);

  double bw_frac = get_options()->TrustMinBWWeightFractionGuard;
  if(bw_frac <= 0.0f) {
    bw_frac = get_options()->TrustMinBWWeightFraction;
  }

  double bw_required = bw_weight_total * bw_frac;
  smartlist_sort(acceptable, _trust_compare_guard_scores);

  while(smartlist_len(acceptable) > 0 && bw_weight_choices < bw_required) {
    node_t* node = smartlist_pop_last(acceptable);
    double node_weight = (double)node->rs->bandwidth_kb;
    bw_weight_choices += node_weight;
    smartlist_add(choices, node);
  }

  log_notice(LD_CIRC, "trust: guard_scores_max=%f uncomp_thresh=%f-%f comp_threshold=%f-%f "
      "bw_total=%f bw_safe=%f bw_acceptable=%f bw_choices=%f bw_required=%f "
      "n_potential_guards=%i n_safe_guards=%i n_acceptable_guards=%i n_choices=%i",
       trusti->guard_scores_max,
       acceptable_uncomp_threshold, safe_uncomp_threshold,
       acceptable_comp_threshold, safe_comp_threshold,
       bw_weight_total, bw_weight_safe, bw_weight_acceptable, bw_weight_choices, bw_required,
       guard_count, n_safe_guards, n_acceptable_guards, smartlist_len(choices));

  while(smartlist_len(trusti->my_guards) < 3 && smartlist_len(choices) > 0) {
    const node_t* node = node_sl_choose_by_bandwidth(choices, WEIGHT_FOR_GUARD);
//    in_addr_t node_ip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
    if(!smartlist_contains(trusti->my_guards, node)) {
      _trust_add_guard(node);
    }
    smartlist_remove(choices, node);
  }

  int n_guards = smartlist_len(trusti->my_guards);
  log_info(LD_CIRC, "trust: we have %i guards in pool%s", n_guards,
      n_guards >= 3 ? ", yay!" : n_guards < 1 ? ", circuits will fail without guards!!" : "");

  smartlist_free(choices);
  smartlist_free(acceptable);
}

static void _trust_choose_guards() {
  if(get_options()->SelectPathsWithTrustOne) {
    _trust_choose_guards_trustone();
  } else {
    _trust_choose_guards_trustall();
  }
}

static const node_t* trust_choose_middle_node() {
  smartlist_t* choices = smartlist_new();

  SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
    if(node->is_fast && node->is_running && node->is_valid
        && _trust_node_has_info(node)) {
        //in_addr_t node_ip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
        smartlist_add(choices, node);
    }
  );

  const node_t* middle_node = node_sl_choose_by_bandwidth(choices, WEIGHT_FOR_MID);
  smartlist_free(choices);
  return middle_node;
}

static const node_t* _trust_get_acceptable_exits_trustone(in_addr_t guard_netip, unsigned int dest_asn, char* dest_address, smartlist_t** choices_out) {
  /* figure out which exits are suitable for this guard and dest */
  double bw_weight_total = 0.0f;
  double bw_weight_choices = 0.0f;

  smartlist_t* choices = smartlist_new();
  smartlist_t* allexits = smartlist_new();
  node_t* guard_node = NULL;

  /* need these stored for the _trust_compare_exit_scores call */
  trusti->guard_netip_temp = guard_netip;
  trusti->dest_asn_temp = dest_asn;

  SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
    in_addr_t node_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
    if(node->is_exit && !node->is_bad_exit &&
        node->is_fast && node->is_running && node->is_valid) {
      double weight = (double)node->rs->bandwidth_kb;
      bw_weight_total += weight;
      smartlist_add(allexits, node);
    }

    if(node_netip == guard_netip) {
      guard_node = node;
    }
  );

  int exit_count = smartlist_len(allexits);

  double bw_required = bw_weight_total * get_options()->TrustMinBWWeightFraction;
  smartlist_sort(allexits, _trust_compare_exit_scores);

  double max_exit_score = 0.0f;

  while(smartlist_len(allexits) > 0 && bw_weight_choices < bw_required) {
    node_t* node = smartlist_pop_last(allexits);
    double node_weight = (double)node->rs->bandwidth_kb;
    bw_weight_choices += node_weight;
    smartlist_add(choices, node);

    if(max_exit_score == 0.0f) {
      in_addr_t exit_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
      max_exit_score = trustdb_get_exit_score(trusti->tdb, guard_netip, exit_netip, dest_asn);
    }
  }

  const node_t* exit_node = node_sl_choose_by_bandwidth(choices, WEIGHT_FOR_EXIT);

  /* this is only a real path build if choices_out is NULL */
  if(!choices_out) {
    log_notice(LD_CIRC, "trust: exit_scores_max=%f "
        "bw_total=%f bw_choices=%f bw_required=%f "
        "n_potential_exits=%i n_choices=%i "
        "chosen_exit=%s guard=%s destination=%s",
        max_exit_score,
         bw_weight_total, bw_weight_choices, bw_required,
         exit_count, smartlist_len(choices),
         exit_node->ri ? exit_node->ri->nickname : exit_node->rs ? exit_node->rs->nickname : "unknown",
         guard_node && guard_node->ri ? guard_node->ri->nickname : guard_node && guard_node->rs ? guard_node->rs->nickname : "unknown",
         dest_address);
  }

  trusti->guard_netip_temp = 0;
  trusti->dest_asn_temp = 0;

  if(choices_out){
    *choices_out = choices;
  } else {
    smartlist_free(choices);
  }
  smartlist_free(allexits);
  return exit_node;
}

//XXX FIXME dont loop twice
static const node_t* _trust_get_acceptable_exits_trustall(in_addr_t guard_netip, unsigned int dest_asn, char* dest_address, smartlist_t** choices_out) {
  /* figure out which exits are suitable for this guard and dest */
  double max_exit_score = 0.0f;
  int exit_count = 0;
  double bw_weight_total = 0.0f;
  double bw_weight_safe = 0.0f;
  double bw_weight_acceptable = 0.0f;
  double bw_weight_choices = 0.0f;

  node_t* guard_node = NULL;

  /* need these stored for the _trust_compare_exit_scores call */
  trusti->guard_netip_temp = guard_netip;
  trusti->dest_asn_temp = dest_asn;

  SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
    in_addr_t node_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
    if(node->is_exit && !node->is_bad_exit &&
        node->is_fast && node->is_running && node->is_valid) {
      exit_count++;
      double weight = (double)node->rs->bandwidth_kb;
      bw_weight_total += weight;

      double score = trustdb_get_exit_score(trusti->tdb, guard_netip, node_netip, dest_asn);
      if(score >= 0.0f && score > max_exit_score) {
        max_exit_score = score;
      }
    }

    if(node_netip == guard_netip) {
      guard_node = node;
    }
  );

  smartlist_t* choices = smartlist_new();
  smartlist_t* acceptable = smartlist_new();

  double safe_uncomp_threshold = max_exit_score * get_options()->TrustSafeExitUncompThresh;
  double safe_comp_threshold = (1.0f - max_exit_score) * get_options()->TrustSafeExitCompThresh;
  double acceptable_uncomp_threshold = max_exit_score * get_options()->TrustAcceptableExitUncompThresh;
  double acceptable_comp_threshold = (1.0f - max_exit_score) * get_options()->TrustAcceptableExitCompThresh;

//  char guardname[32];
//  memset(guardname, 0, 32);
//  tor_addr_to_str(guardname, (const tor_addr_t*)&guard_netip, 32, 0);
//  log_info(LD_CIRC, "trust: from %i exits for destination asn %u and guard %u (%s), max exit score is %f, uncomp_thresh is %f, comp_thresh is %f",
//              exit_count, dest_asn, guard_netip, guardname, max_exit_score, uncomp_threshold, comp_threshold);

  //(score >= top_exit_score*uncomp_threshold) and
  //(1-score <= (1-top_exit_score)*comp_threshold)
  SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
    if(node->is_exit && !node->is_bad_exit &&
        node->is_fast && node->is_running && node->is_valid
        && _trust_node_has_info(node)) {
      double weight = (double)node->rs->bandwidth_kb;
      in_addr_t potential_exit_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
      double score = trustdb_get_exit_score(trusti->tdb, guard_netip, potential_exit_netip, dest_asn);

      if(score >= safe_uncomp_threshold && (1.0f - score) <= safe_comp_threshold) {
        smartlist_add(choices, node);
        bw_weight_safe += weight;
        bw_weight_choices += weight;
      } else if(score >= acceptable_uncomp_threshold && (1.0f - score) <= acceptable_comp_threshold) {
        smartlist_add(acceptable, node);
        bw_weight_acceptable += weight;
      }
    }
  );

  int n_safe_exits = smartlist_len(choices);
  int n_acceptable_exits = smartlist_len(acceptable);

  double bw_required = bw_weight_total * get_options()->TrustMinBWWeightFraction;
  smartlist_sort(acceptable, _trust_compare_exit_scores);

  while(smartlist_len(acceptable) > 0 && bw_weight_choices < bw_required) {
    node_t* node = smartlist_pop_last(acceptable);
    double node_weight = (double)node->rs->bandwidth_kb;
    bw_weight_choices += node_weight;
    smartlist_add(choices, node);
  }

  const node_t* exit_node = node_sl_choose_by_bandwidth(choices, WEIGHT_FOR_EXIT);

//  gchar* ipstrbuf = g_malloc0(INET6_ADDRSTRLEN+1);
//  const gchar* guard_ip_str = inet_ntop(AF_INET, &guard_netip, ipstrbuf, INET6_ADDRSTRLEN);
//  g_free(ipstrbuf);

  /* this is only a real path build if choices_out is NULL */
  if(!choices_out) {
    log_notice(LD_CIRC, "trust: exit_scores_max=%f uncomp_thresh=%f-%f comp_threshold=%f-%f "
        "bw_total=%f bw_safe=%f bw_acceptable=%f bw_choices=%f bw_required=%f "
        "n_potential_exits=%i n_safe_exits=%i n_acceptable_exits=%i n_choices=%i "
        "chosen_exit=%s guard=%s destination=%s",
         max_exit_score,
         acceptable_uncomp_threshold, safe_uncomp_threshold,
         acceptable_comp_threshold, safe_comp_threshold,
         bw_weight_total, bw_weight_safe, bw_weight_acceptable, bw_weight_choices, bw_required,
         exit_count, n_safe_exits, n_acceptable_exits, smartlist_len(choices),
         exit_node->ri ? exit_node->ri->nickname : exit_node->rs ? exit_node->rs->nickname : "unknown",
         guard_node && guard_node->ri ? guard_node->ri->nickname : guard_node && guard_node->rs ? guard_node->rs->nickname : "unknown",
         dest_address);
  }

  trusti->guard_netip_temp = 0;
  trusti->dest_asn_temp = 0;

  if(choices_out){
	  *choices_out = choices;
  } else {
	  smartlist_free(choices);
  }
  smartlist_free(acceptable);
  return exit_node;
}

static const node_t* _trust_get_acceptable_exits(in_addr_t guard_netip, unsigned int dest_asn, char* dest_address, smartlist_t** choices_out) {
  if(get_options()->SelectPathsWithTrustOne) {
    return _trust_get_acceptable_exits_trustone(guard_netip, dest_asn, dest_address, choices_out);
  } else {
    return _trust_get_acceptable_exits_trustall(guard_netip, dest_asn, dest_address, choices_out);
  }
}

int trust_circuit_is_ok_for_dest(const entry_connection_t *conn,
                             const origin_circuit_t *circ) {
  tor_assert(get_options()->SelectPathsWithTrust);
  tor_assert(circ);
  if(!trusti || !circ)
    return 1; // we have not initialized our trust module yet

  if(!circ->was_built_with_trust)
    return 0;

  if(smartlist_len(trusti->my_guards) < 3) {
    _trust_choose_guards();
  }

  crypt_path_t* first = circ->cpath;
  crypt_path_t* next = first->next;
  crypt_path_t* last = first->prev;

  in_addr_t guard_ip = first->extend_info->addr.addr.in_addr.s_addr;
  in_addr_t middle_ip = next->extend_info->addr.addr.in_addr.s_addr;
  in_addr_t exit_ip = last->extend_info->addr.addr.in_addr.s_addr;

  if(smartlist_len(trusti->my_guards) < 1) {
    /* we have no guards, we have no way to tell if this circuit is ok yet */

    char* addrStr = trust_get_circ_addr_string(guard_ip, middle_ip, exit_ip);

    log_notice(LD_CIRC, "trust: default accepting circuit %s (%s->%s->%s) for dest %s because we have no guards yet",
        addrStr,
          first->extend_info ? first->extend_info->nickname : "unknown",
          next->extend_info ? next->extend_info->nickname : "unknown",
        last->extend_info ? last->extend_info->nickname : "unknown",
        conn->original_dest_address);

    free(addrStr);
    return 1;
  }

  /* true if the existing guard-exit pair on circ could have
   * plausibly been chosen for dest on conn, false otherwise. */

  /* get destination info */
  unsigned int dest_asn = _trust_get_dest_asn(conn);

  log_info(LD_CIRC, "trust: checking circuit ok for dest %s asn %u",
        conn->original_dest_address, dest_asn);

  /* look for which exits could be used with this destination */
  int found = 0;

  smartlist_t* choices = NULL;
  _trust_get_acceptable_exits(guard_ip, dest_asn, conn->original_dest_address, &choices);
  SMARTLIST_FOREACH(choices, node_t *, node,
    in_addr_t potential_exit_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
    if(potential_exit_netip == exit_ip) {
      found = 1;
      break;
    }
  );
  smartlist_free(choices);

  char* addrStr = trust_get_circ_addr_string(guard_ip, middle_ip, exit_ip);
  log_notice(LD_CIRC, "trust: existing %s circuit %s (%s->%s->%s) is %ssuitable for dest %s from asn %u",
      circ->was_built_with_trust ? "trusted" : "untrusted",
      addrStr,
      first->extend_info ? first->extend_info->nickname : "unknown",
      next->extend_info ? next->extend_info->nickname : "unknown",
      last->extend_info ? last->extend_info->nickname : "unknown",
	  found ? "" : "un",
			 conn->original_dest_address, dest_asn);
  free(addrStr);
  
  return found ? 1 : 0;
}

int trust_needs_trust(uint8_t purpose, int flags) {
  if(get_options()->SelectPathsWithTrust &&
      purpose == CIRCUIT_PURPOSE_C_GENERAL &&
		  (flags & CIRCLAUNCH_IS_INTERNAL) == 0) {
    return 1;
  } else {
	  return 0;
  }
}
// circuit_establish_circuit() in circuitbuild.c

/*
 * path selection
 *
 * 1 choose 3 guards from guard set and weighted by bandwidth based on asn
 * 2 for new dest, find dest cluster
 *  -combining dest cluster with guard cluster will give you exit cluster
 *  -choose exit weighted by bw
 *
 * preemptive circuits
 *
 * for new streams, re-use circuit if the existing guard-exit pair could have
 * been chosen for the new destination, and then if its not used over 10 minutes
 * (MaxCircuitDirtiness)
 */

int trust_choose_cpath(const entry_connection_t *conn, origin_circuit_t *circ) {
  tor_assert(get_options()->SelectPathsWithTrust);

  if(smartlist_len(trusti->my_guards) < 3) {
    _trust_choose_guards();
    if(smartlist_len(trusti->my_guards) < 1) {
      log_warn(LD_CIRC, "trust: no guards for circuit, failing");
      return -1;
    }
  }

  unsigned int dest_asn = _trust_get_dest_asn(conn);
  log_info(LD_CIRC, "trust: building circuit for dest %s asn %u",
      conn->original_dest_address, dest_asn);

  /* choose 1 of my 3 guards at random */
  const node_t* guard_node = smartlist_choose(trusti->my_guards);
  in_addr_t guard_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(guard_node));

  const node_t* entry_node = guard_node;
  const node_t* exit_node = _trust_get_acceptable_exits(guard_netip, dest_asn, conn->original_dest_address, NULL);
  const node_t* middle_node = trust_choose_middle_node();

  if(!entry_node || !middle_node || !exit_node) {
    log_warn(LD_CIRC, "trust: missing nodes for circuit, failing");
    return -1;
  }

  if(!_trust_node_has_info(entry_node) ||
      !_trust_node_has_info(middle_node) ||
      !_trust_node_has_info(exit_node)) {
    log_warn(LD_CIRC, "trust: missing node extend infos for circuit, failing");
    return -1;
  }

  char* addrStr = trust_get_circ_addr_string(
		  entry_node->ri ? entry_node->ri->addr : 0,
		  middle_node->ri ? middle_node->ri->addr : 0,
		  exit_node->ri ? exit_node->ri->addr : 0);

  log_notice(LD_CIRC, "trust: successfully chose path %s (%s->%s->%s) for dest %s in asn %u",
		  addrStr,
		  entry_node->ri ? entry_node->ri->nickname : entry_node->rs ? entry_node->rs->nickname : "unknown",
		  middle_node->ri ? middle_node->ri->nickname : middle_node->rs ? middle_node->rs->nickname : "unknown",
		  exit_node->ri ? exit_node->ri->nickname : exit_node->rs ? exit_node->rs->nickname : "unknown",
			 conn->original_dest_address, dest_asn);

  free(addrStr);

  circ->build_state->desired_path_len = 3;

  extend_info_t* entry_info = extend_info_from_node(entry_node, 0);
  tor_assert(entry_info);
  onion_append_hop(&circ->cpath, entry_info);
  extend_info_free(entry_info);

  extend_info_t* middle_info = extend_info_from_node(middle_node, 0);
  tor_assert(middle_info);
  onion_append_hop(&circ->cpath, middle_info);
  extend_info_free(middle_info);

  extend_info_t* exit_info = extend_info_from_node(exit_node, 0);
  tor_assert(exit_info);
  onion_append_hop(&circ->cpath, exit_info);
  circ->build_state->chosen_exit = exit_info;
  //extend_info_free(exit_info);

  circ->was_built_with_trust = 1;

  return 0;
}
