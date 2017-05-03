/*
 * trustlib.c
 *
 *  Created on: Jul 23, 2014
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
#include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>

typedef struct trustdb_vlink_s {
  char* adversary_str; // eg, as-888|ix-org-22|...
  GQueue* adversary_str_parts; // queue of strings, each part between the pipes
  int has_guard_score;
  double guard_score;
} trustdb_vlink_t;

typedef struct trustdb_cluster_s {
  GHashTable* vlinks; // (guardid|exitid) -> trustdb_vlink_t*
} trustdb_cluster_t;

typedef struct trustdb_internal_s {
  int refcount;
  GHashTable* src_cluster_ids; // client asn -> src cluster id
  GHashTable* src_clusters; // src cluster id -> trustdb_cluster_s*
  GHashTable* dst_cluster_ids; // server asn -> dst cluster id
  GHashTable* dst_clusters; // dst cluster id -> trustdb_cluster_s*
  GHashTable* guard_ids; // guard ip -> guard id
  GHashTable* exit_ids; // exit ip -> exit id
  GHashTable* adv_codes; // "as-"|"ixp-" -> "cc" (adv component to country code)
  unsigned int num_countries;
} trustdb_internal_t;

struct trustdb_s {
  char* cc;
  unsigned int asn;
  in_addr_t ip;
  trustdb_internal_t* internal;
};

static in_addr_t _trustdb_hostname_to_ip(const char* hostname) {
  in_addr_t netip = INADDR_NONE;
  struct addrinfo* info;
  if(getaddrinfo(hostname, NULL, NULL, &info) != -1) {
    netip = ((struct sockaddr_in*)(info->ai_addr))->sin_addr.s_addr;
  }
  return netip;
}

static trustdb_vlink_t* _trustdb_vlink_new(const char* adversaries_str) {
  trustdb_vlink_t* a = g_new0(trustdb_vlink_t, 1);
  if(adversaries_str) {
    a->adversary_str = strdup(adversaries_str);
    a->adversary_str_parts = g_queue_new();

    char* saveptr = NULL;
    char* adv_part = strtok_r(a->adversary_str, "|", &saveptr);
    while(adv_part) {
      g_queue_push_tail(a->adversary_str_parts, strdup(adv_part));
      adv_part = strtok_r(NULL, "|", &saveptr);
    }
  }
  return a;
}

static void _trustdb_vlink_free(trustdb_vlink_t* vlink) {
  if(vlink) {
    if(vlink->adversary_str) {
      g_free(vlink->adversary_str);
    }
    if(vlink->adversary_str_parts) {
      g_queue_free_full(vlink->adversary_str_parts, g_free);
    }
    g_free(vlink);
  }
}

static trustdb_cluster_t* _trustdb_cluster_new() {
  trustdb_cluster_t* cluster = g_new0(trustdb_cluster_t, 1);
  cluster->vlinks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)_trustdb_vlink_free);
  return cluster;
}

static void _trustdb_cluster_free(trustdb_cluster_t* cluster) {
  if(cluster) {
    if(cluster->vlinks) {
      g_hash_table_destroy(cluster->vlinks);
    }
    g_free(cluster);
  }
}

static void _trustdb_cluster_add_adversaries(trustdb_cluster_t* cluster,
    unsigned int relay_id, const char* adversaries_str) {
  if(!g_hash_table_lookup(cluster->vlinks, GUINT_TO_POINTER(relay_id))) {
    trustdb_vlink_t* vlink = _trustdb_vlink_new(adversaries_str);
    g_hash_table_replace(cluster->vlinks, GUINT_TO_POINTER(relay_id), vlink);
  }
}

static GHashTable* _trustdb_parse_asn_cluster_id_file(const char* filename) {
  smartlist_t* lines = smartlist_new();

  char* contents = read_file_to_str(filename, 0, NULL);
  tor_split_lines(lines, contents, strlen(contents));

  char* saveptr = NULL;
  char* asn_token = NULL;
  char* cluster_id_token = NULL;
  unsigned int nlines = 0;

  GHashTable* cluster_ids = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

  SMARTLIST_FOREACH_BEGIN(lines, char*, line) {
    if(!line)
      continue;
    if(!nlines++) // skip header, increments after compare
      continue;

    asn_token = strtok_r(line, ",", &saveptr);
    tor_assert(asn_token);
    unsigned int asn = (unsigned int) atoi(asn_token);

    cluster_id_token = strtok_r(NULL, ",", &saveptr);
    tor_assert(cluster_id_token);
    unsigned int cluster_id = (unsigned int) atoi(cluster_id_token);

    g_hash_table_replace(cluster_ids, GUINT_TO_POINTER(asn), GUINT_TO_POINTER(cluster_id));
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(lines);
  tor_free(contents);

  return cluster_ids;
}

/** example format:
asn,clusid
8359,1
19262,2
16880,2
4589,3
 */
static GHashTable* _trustdb_parse_clients(const char* filename) {
  GHashTable* src_cluster_ids = _trustdb_parse_asn_cluster_id_file(filename);
  tor_assert(g_hash_table_size(src_cluster_ids) > 0);
  return src_cluster_ids;
}

/** example format:
asn,clusid
20782,1
14618,2
 */
static GHashTable* _trustdb_parse_servers(const char* filename) {
  GHashTable* dst_cluster_ids = _trustdb_parse_asn_cluster_id_file(filename);
  tor_assert(g_hash_table_size(dst_cluster_ids) > 0);
  return dst_cluster_ids;
}

static GHashTable* _trustdb_parse_relay_id_ip_file(const char* filename) {
  smartlist_t* lines = smartlist_new();

  char* contents = read_file_to_str(filename, 0, NULL);
  tor_split_lines(lines, contents, strlen(contents));

  char* saveptr = NULL;
  char* id_token = NULL;
  char* ip_token = NULL;
  unsigned int nlines = 0;

  GHashTable* ids = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

  SMARTLIST_FOREACH_BEGIN(lines, char*, line) {
    if(!line)
      continue;
    if(!nlines++) // skip header, increments after compare
      continue;

    id_token = strtok_r(line, ",", &saveptr);
    tor_assert(id_token);
    unsigned int id = (unsigned int)atoi(id_token);

    ip_token = strtok_r(NULL, ",", &saveptr);
    tor_assert(ip_token);

    struct in_addr inaddr;
    tor_assert(1 == inet_pton(AF_INET, ip_token, &inaddr));
    in_addr_t netip = inaddr.s_addr;

    g_hash_table_replace(ids, GUINT_TO_POINTER(netip), GUINT_TO_POINTER(id));
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(lines);
  tor_free(contents);

  return ids;
}

/** example format:
gid,ip
1,109.111.158.217
2,178.5.119.222
3,178.5.119.222
4,208.83.93.50
 */
static GHashTable* _trustdb_parse_guards(const char* filename) {
  /* we should have some guard options */
  GHashTable* guard_ids = _trustdb_parse_relay_id_ip_file(filename);
  tor_assert(g_hash_table_size(guard_ids) > 0);
  return guard_ids;
}

/** example format:
eid,ip
1,109.111.158.217
2,178.5.119.222
3,109.111.158.217
 */
static GHashTable* _trustdb_parse_exits(const char* filename) {
  /* we should have some guard options */
  GHashTable* exit_ids = _trustdb_parse_relay_id_ip_file(filename);
  tor_assert(g_hash_table_size(exit_ids) > 0);
  return exit_ids;
}

static GHashTable* _trustdb_parse_clusters(const char* filename) {
  smartlist_t* lines = smartlist_new();

  char* contents = read_file_to_str(filename, 0, NULL);
  tor_split_lines(lines, contents, strlen(contents));

  char* saveptr = NULL;
  char* cluster_id_token = NULL;
  char* relay_id_token = NULL;
  char* adversaries_token = NULL;
  unsigned int nlines = 0;

  GHashTable* clusters = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)_trustdb_cluster_free);

  SMARTLIST_FOREACH_BEGIN(lines, char*, line) {
    if(!line)
      continue;
    if(!nlines++) // skip header, increments after compare
      continue;

    cluster_id_token = strtok_r(line, ",", &saveptr);
    tor_assert(cluster_id_token);
    unsigned int cluster_id = (unsigned int) atoi(cluster_id_token);

    trustdb_cluster_t* cluster = g_hash_table_lookup(clusters, GUINT_TO_POINTER(cluster_id));
    if(!cluster) {
      cluster = _trustdb_cluster_new();
      g_hash_table_replace(clusters, GUINT_TO_POINTER(cluster_id), cluster);
    }

    relay_id_token = strtok_r(NULL, ",", &saveptr);
    tor_assert(relay_id_token);
    unsigned int relay_id = (unsigned int) atoi(relay_id_token);

    adversaries_token = strtok_r(NULL, ",", &saveptr);

    _trustdb_cluster_add_adversaries(cluster, relay_id, adversaries_token);
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(lines);
  tor_free(contents);

  return clusters;
}

/** example format:
clusid,gid,advs
1,1,z
1,2,y
1,3,x
1,4,w
2,1,v
2,2,u
2,3,t
2,4,s
3,1,r
3,2,q
3,3,p
3,4,o
 */
static GHashTable* _trust_parse_adversaries_in(const char* filename) {
  GHashTable* clusters_in = _trustdb_parse_clusters(filename);
  g_assert(g_hash_table_size(clusters_in) > 0);
  return clusters_in;
}

/** example format:
clusid,eid,advs
1,1,
1,2,a|b|c
1,3,d
2,1,e
2,2,f
2,3,g
 */
static GHashTable* _trust_parse_adversaries_out(const char* filename) {
  GHashTable* clusters_out = _trustdb_parse_clusters(filename);
  g_assert(g_hash_table_size(clusters_out) > 0);
  return clusters_out;
}


/**
adv,code
as-1,us
ixp-4,de
ixp-1,au
n/a,fr
...
 */
static GHashTable* _trust_parse_countries(const char* filename) {
  smartlist_t* lines = smartlist_new();

  char* contents = read_file_to_str(filename, 0, NULL);
  tor_split_lines(lines, contents, strlen(contents));

  char* saveptr = NULL;
  char* adv_token = NULL;
  char* cc_token = NULL;
  unsigned int nlines = 0;

  GHashTable* ccht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

  SMARTLIST_FOREACH_BEGIN(lines, char*, line) {
    if(!line)
      continue;
    if(!nlines++) // skip header, increments after compare
      continue;

    adv_token = strtok_r(line, ",", &saveptr);
    tor_assert(adv_token);
    cc_token = strtok_r(NULL, ",", &saveptr);
    tor_assert(cc_token);
    g_hash_table_replace(ccht, g_ascii_strdown(adv_token, -1), g_ascii_strdown(cc_token, -1));
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(lines);
  tor_free(contents);

  return ccht;
}

/** example format:
clusid,gid,score
1,1,0.375
1,2,0.17
1,3,0.68
1,4,0.95
2,1,0.5
2,2,0.0
2,3,0.87
2,4,0.12
3,1,0.29
3,2,0.33
3,3,0.47
3,4,0.81
 */
static void _trust_parse_guard_scores(GHashTable* src_clusters, const char* filename) {
  smartlist_t* lines = smartlist_new();

  char* contents = read_file_to_str(filename, 0, NULL);
  tor_split_lines(lines, contents, strlen(contents));

  char* saveptr = NULL;
  char* cluster_id_token = NULL;
  char* guard_id_token = NULL;
  char* score_token = NULL;
  unsigned int nlines = 0;

  SMARTLIST_FOREACH_BEGIN(lines, char*, line) {
    if(!line)
      continue;
    if(!nlines++) // skip header, increments after compare
      continue;

    cluster_id_token = strtok_r(line, ",", &saveptr);
    tor_assert(cluster_id_token);
    unsigned int cluster_id = (unsigned int) atoi(cluster_id_token);

    trustdb_cluster_t* cluster = g_hash_table_lookup(src_clusters, GUINT_TO_POINTER(cluster_id));
    if(!cluster) {
      cluster = _trustdb_cluster_new();
      g_hash_table_replace(src_clusters, GUINT_TO_POINTER(cluster_id), cluster);
    }

    guard_id_token = strtok_r(NULL, ",", &saveptr);
    tor_assert(guard_id_token);
    unsigned int guard_id = (unsigned int) atoi(guard_id_token);

    trustdb_vlink_t* vlink = g_hash_table_lookup(cluster->vlinks, GUINT_TO_POINTER(guard_id));
    if(!vlink) {
      _trustdb_cluster_add_adversaries(cluster, guard_id, NULL);
    }

    vlink = g_hash_table_lookup(cluster->vlinks, GUINT_TO_POINTER(guard_id));
    tor_assert(vlink);

    score_token = strtok_r(NULL, ",", &saveptr);
    if(score_token) {
      vlink->guard_score = strtod(score_token, NULL);
      vlink->has_guard_score = 1;
      if(vlink->guard_score < 0.0 || vlink->guard_score > 1.0) {
        log_err(LD_BUG, "trustdb: parsed guard score %f from token %s is out of range",
            vlink->guard_score, score_token);
        tor_assert(0);
      }
    }
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(lines);
  tor_free(contents);
}

static trustdb_vlink_t* _trust_get_vlink_in(trustdb_t* tdb, in_addr_t guard_netip,
    unsigned int src_asn) {
  gpointer src_cluster_id = NULL;
  gboolean exists = g_hash_table_lookup_extended(tdb->internal->src_cluster_ids,
      GUINT_TO_POINTER(src_asn), NULL, &src_cluster_id);

  if(!exists) {
    log_warn(LD_GENERAL, "trustdb: unable to find src cluster id for asn %u", src_asn);
    return NULL;
  }

  trustdb_cluster_t* src_cluster = NULL;
  exists = g_hash_table_lookup_extended(tdb->internal->src_clusters, src_cluster_id, NULL, (gpointer*)&src_cluster);

  if(!exists || !src_cluster) {
    log_warn(LD_GENERAL, "trustdb: unable to find src cluster from id %u and asn %u",
        GPOINTER_TO_UINT(src_cluster_id), src_asn);
    return NULL;
  }

  gpointer guard_id = NULL;
  exists = g_hash_table_lookup_extended(tdb->internal->guard_ids, GUINT_TO_POINTER(guard_netip), NULL, &guard_id);

  if(!exists) {
    char ip[INET6_ADDRSTRLEN];
    memset(ip, 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &guard_netip, ip, INET6_ADDRSTRLEN);
    log_warn(LD_GENERAL, "trustdb: unable to find guard id from guard ip %s", ip);
    return NULL;
  }

  trustdb_vlink_t* vlink_in = NULL;
  exists = g_hash_table_lookup_extended(src_cluster->vlinks, guard_id, NULL, (gpointer*)&vlink_in);

  if(!exists || !vlink_in) {
    log_warn(LD_GENERAL, "trustdb: unable to find vlink_in from src cluster id %u asn %u and guard_id %u",
        GPOINTER_TO_UINT(src_cluster_id), src_asn, GPOINTER_TO_UINT(guard_id));
    return NULL;
  }

  return vlink_in;
}

static trustdb_vlink_t* _trust_get_vlink_out(trustdb_t* tdb, in_addr_t exit_netip,
    unsigned int dst_asn) {
  gpointer dst_cluster_id = NULL;
  gboolean exists = g_hash_table_lookup_extended(tdb->internal->dst_cluster_ids,
      GUINT_TO_POINTER(dst_asn), NULL, &dst_cluster_id);

  if(!exists) {
    log_warn(LD_GENERAL, "trustdb: unable to find dst cluster id for asn %u", dst_asn);
    return NULL;
  }

  trustdb_cluster_t* dst_cluster = NULL;
  exists = g_hash_table_lookup_extended(tdb->internal->dst_clusters, dst_cluster_id, NULL, (gpointer*)&dst_cluster);

  if(!exists || !dst_cluster) {
    log_warn(LD_GENERAL, "trustdb: unable to find dst cluster from id %u and asn %u",
        GPOINTER_TO_UINT(dst_cluster_id), dst_asn);
    return NULL;
  }

  gpointer exit_id = NULL;
  exists = g_hash_table_lookup_extended(tdb->internal->exit_ids, GUINT_TO_POINTER(exit_netip), NULL, &exit_id);

  if(!exists) {
    char ip[INET6_ADDRSTRLEN];
    memset(ip, 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &exit_netip, ip, INET6_ADDRSTRLEN);
    log_warn(LD_GENERAL, "trustdb: unable to find exit id from exit ip %s", ip);
    return NULL;
  }

  trustdb_vlink_t* vlink_out = NULL;
  exists = g_hash_table_lookup_extended(dst_cluster->vlinks, exit_id, NULL, (gpointer*)&vlink_out);

  if(!exists || !vlink_out) {
    log_warn(LD_GENERAL, "trustdb: unable to find vlink_out from dst cluster id %u asn %u and exit_id %u",
        GPOINTER_TO_UINT(dst_cluster_id), dst_asn, GPOINTER_TO_UINT(exit_id));
    return NULL;
  }

  return vlink_out;
}

static gboolean _trust_is_exposed(trustdb_t* tdb,
    smartlist_t* existing_guards, trustdb_vlink_t* vlink, const char* adv) {

  int i = 0;
  SMARTLIST_FOREACH(existing_guards, node_t*, existing_guard, {
    in_addr_t guard_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(existing_guard));

    /* if we are considering a guard in the same vlink, then we are
     * already exposed to all the same components */
    trustdb_vlink_t* vlink_in = _trust_get_vlink_in(tdb, guard_netip, tdb->asn);
    if(!vlink_in || vlink == vlink_in) {
      return TRUE;
    }

    // check all components on vlink from client to guard
    guint inqlen = g_queue_get_length(vlink_in->adversary_str_parts);

    // this for loop is basically a queue iterator
    for(i = 0; i < inqlen; i++) {
      char* adv_in = g_queue_pop_head(vlink_in->adversary_str_parts);

      if(adv_in && !g_ascii_strcasecmp(adv, adv_in)) {
        return TRUE;
      }

      g_queue_push_tail(vlink_in->adversary_str_parts, adv_in);
    }
  });

  return FALSE;
}

static void _trust_add_exposed_codes(trustdb_t* tdb, smartlist_t* nodes, GHashTable* countries,
    unsigned int asn, int isexit) {
  int i = 0;
  SMARTLIST_FOREACH(nodes, node_t*, node, {
    in_addr_t node_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));

    char node_code[32];
    memset(node_code, 0, 32);
    if(trust_get_cc(node_netip, node_code)) {
      g_hash_table_replace(countries, g_strdup(node_code), NULL);
    }

    trustdb_vlink_t* vlink = NULL;
    if(isexit) {
      vlink = _trust_get_vlink_out(tdb, node_netip, asn);
    } else {
      vlink = _trust_get_vlink_in(tdb, node_netip, asn);
    }

    if(vlink) {
      // check all components on vlink
      guint inqlen = g_queue_get_length(vlink->adversary_str_parts);

      // this for loop is basically a queue iterator
      for(i = 0; i < inqlen; i++) {
        char* adv = g_queue_pop_head(vlink->adversary_str_parts);
        if(adv) {
          char* code = g_hash_table_lookup(tdb->internal->adv_codes, adv);
          if(code) {
            if(g_strstr_len(code, -1, "|") != NULL) {
              gchar** codes = g_strsplit(code, "|", 0);
              gint j = 0;
              gchar* c = NULL;
              for(j = 0; (c = codes[j]) != NULL; j++) {
                g_hash_table_replace(countries, g_strdup(c), NULL);
              }
              g_strfreev(codes);
            } else {
              g_hash_table_replace(countries, g_strdup(code), NULL);
            }
          }
        }
        g_queue_push_tail(vlink->adversary_str_parts, adv);
      }
    }
  });
}

static double _trust_get_guard_score_country(trustdb_t* tdb,
    smartlist_t* existing_guards, const node_t* guard_to_score) {
  // to track the countries we are exposed to
  GHashTable* countries_exposed = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  // add client country
  g_hash_table_replace(countries_exposed, g_strdup(tdb->cc), NULL);

  //add existing guard and link countries
  _trust_add_exposed_codes(tdb, existing_guards, countries_exposed, tdb->asn, 0);
  double num_exposed_current = (double) g_hash_table_size(countries_exposed);

  // the potential new guard
  smartlist_t* new_guard = smartlist_new();
  smartlist_add(new_guard, guard_to_score);
  _trust_add_exposed_codes(tdb, new_guard, countries_exposed, tdb->asn, 0);
  smartlist_free(new_guard);
  double num_exposed_new = (double) g_hash_table_size(countries_exposed);

  // compute scores
  double num_total = (double) tdb->internal->num_countries;
  double score_max = num_total - num_exposed_current;
  double score_new = num_total - num_exposed_new;
  double score = score_new / score_max;

  g_hash_table_destroy(countries_exposed);
  return score;
}

node_t* _trust_get_node_helper(in_addr_t find_netip) {
  node_t* found_node = NULL;
  SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
    in_addr_t node_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(node));
    if(node_netip == find_netip) {
      found_node = node;
      break;
    }
  );
  return found_node;
}

static double _trust_get_exit_score_country(trustdb_t* tdb, in_addr_t guard_netip,
    in_addr_t exit_netip, unsigned int dst_asn) {
  node_t* guard = _trust_get_node_helper(guard_netip);
  tor_assert(guard);
  node_t* exit_to_score = _trust_get_node_helper(exit_netip);
  tor_assert(exit_to_score);

  // to track the countries we are exposed to
  GHashTable* countries_exposed = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  // add client country
  g_hash_table_replace(countries_exposed, g_strdup(tdb->cc), NULL);

  // TODO should this consider all existing guards, not just the one we happen
  // to be using right now??
  //add existing guard and link countries
  smartlist_t* existing_guard = smartlist_new();
  smartlist_add(existing_guard, guard);
  _trust_add_exposed_codes(tdb, existing_guard, countries_exposed, tdb->asn, 0);
  smartlist_free(existing_guard);
  double num_exposed_current = (double) g_hash_table_size(countries_exposed);

  // the potential new exit
  smartlist_t* new_exit = smartlist_new();
  smartlist_add(new_exit, exit_to_score);
  _trust_add_exposed_codes(tdb, new_exit, countries_exposed, dst_asn, 1);
  smartlist_free(new_exit);
  double num_exposed_new = (double) g_hash_table_size(countries_exposed);

  // compute scores
  double num_total = (double) tdb->internal->num_countries;
  double score_max = num_total - num_exposed_current;
  double score_new = num_total - num_exposed_new;
  double score = score_new / score_max;

  g_hash_table_destroy(countries_exposed);
  return score;
}

static double _trust_get_guard_score_theman(trustdb_t* tdb,
    smartlist_t* existing_guards, const node_t* guard_to_score) {
  tor_assert(existing_guards && guard_to_score);

  double uncomp_prob = 1.0f;

  // add the link to the potential new guard
  in_addr_t guard_netip = (in_addr_t)htonl(node_get_prim_addr_ipv4h(guard_to_score));
  trustdb_vlink_t* vlink_in = _trust_get_vlink_in(tdb, guard_netip, tdb->asn);
  if(!vlink_in) {
    return -1.0f; // signal an error
  }

  // for the guard itself
  uncomp_prob *= get_options()->TrustRelayFamilyUncompProb;

  // for all components on vlink from client to guard
  guint inqlen = g_queue_get_length(vlink_in->adversary_str_parts);

  // this for loop is basically a queue iterator
  int i = 0;
  for(i = 0; i < inqlen; i++) {
    char* adv_in = g_queue_pop_head(vlink_in->adversary_str_parts);

    // this only hurts the score if we are not already exposed given
    // our existing guards
    if(!_trust_is_exposed(tdb, existing_guards, vlink_in, adv_in)) {
      if(adv_in && g_str_has_prefix(adv_in, "as-")) {
        uncomp_prob *= get_options()->TrustASORGUncompProb; //TheMan.as_org_uncomp_prob
      } else if(adv_in && g_str_has_prefix(adv_in, "ixp-")) {
        uncomp_prob *= get_options()->TrustIXPORGUncompProb; //TheMan.ixp_org_uncomp_prob
      } else {
        if(adv_in) {
          // warn, delete, continue so we dont consider it again
          log_warn(LD_CIRC, "trustdb: unrecognized adversary: %s", adv_in);
          g_free(adv_in);
        }
        continue;
      }
    }

    g_queue_push_tail(vlink_in->adversary_str_parts, adv_in);
  }

  return uncomp_prob;
}

static double _trust_get_exit_score_theman(trustdb_t* tdb, in_addr_t guard_netip,
    in_addr_t exit_netip, unsigned int dst_asn) {
  tor_assert(tdb && tdb->internal);

  /* get adversaries */
  trustdb_vlink_t* vlink_in = _trust_get_vlink_in(tdb, guard_netip, tdb->asn);
  trustdb_vlink_t* vlink_out = _trust_get_vlink_out(tdb, exit_netip, dst_asn);

//  if(!vlink_in || !vlink_out) {
//    // this shouldnt matter, the missing adversaries simply wont alter the uncomp prob
//    log_debug(LD_CIRC, "trust: problem with vlinks for src cluster %u guard %u exit %u dst cluster %u: vlink_in=%p vlink_out=%p",
//        src_cluster_id, guard_id, exit_id, dst_cluster_id, vlink_in, vlink_out);
//  }

//# relay compromise probability
  double family_uncomp_prob = get_options()->TrustRelayFamilyUncompProb;
  double family_comp_prob = 1.0f - family_uncomp_prob;
  double family_ind_uncomp = 1.0f - (family_comp_prob*family_comp_prob);

//if guard_family_fprints and (exit in guard_family_fprints):
//    relay_uncomp_prob = family_uncomp_prob
//else:
//    relay_uncomp_prob = family_ind_uncomp

  /* relays in shadow have no families */
  double relay_uncomp_prob = family_ind_uncomp;

//# network compromise probability
  double advs_entry_only_uncomp_prob = 1.0f;
  double advs_exit_only_uncomp_prob = 1.0f;
  double advs_in_both_uncomp_prob = 1.0f;

  guint inqlen = 0, outqlen = 0;
  int i = 0, j = 0;

//for entry_adv in entry_advs:
  inqlen = vlink_in ? g_queue_get_length(vlink_in->adversary_str_parts) : 0;
  for(i = 0; i < inqlen; i++) {
    char* adv_in = g_queue_pop_head(vlink_in->adversary_str_parts);

//    if (len(entry_adv) >= 3) and (entry_adv[0:3] == 'as-'):
//        uncomp_prob_adv = TheMan.as_org_uncomp_prob
//    elif (len(entry_adv) >= 4) and (entry_adv[0:4] == 'ixp-'):
//        uncomp_prob_adv = TheMan.ixp_org_uncomp_prob
//    else:
//        logger.info('Unrecognized adversary: {}'.format(entry_adv))
//        continue
    double uncomp_prob = 0.0;
    if(adv_in && g_str_has_prefix(adv_in, "as-")) {
      uncomp_prob = get_options()->TrustASORGUncompProb; //TheMan.as_org_uncomp_prob
    } else if(adv_in && g_str_has_prefix(adv_in, "ixp-")) {
      uncomp_prob = get_options()->TrustIXPORGUncompProb; //TheMan.ixp_org_uncomp_prob
    } else {
      if(adv_in) {
        log_warn(LD_CIRC, "trustdb: unrecognized adversary: %s", adv_in);
        g_free(adv_in);
      }
      continue;
    }

//    if entry_adv in exit_advs:
//        advs_in_both_uncomp_prob *= uncomp_prob_adv
//    else:
//        advs_entry_only_uncomp_prob *= uncomp_prob_adv
    outqlen = vlink_out ? g_queue_get_length(vlink_out->adversary_str_parts) : 0;
    for(j = 0; j < outqlen; j++) {
      char* adv_out = g_queue_pop_head(vlink_out->adversary_str_parts);

      if(adv_out && !g_ascii_strcasecmp(adv_in, adv_out)) {
        advs_in_both_uncomp_prob *= uncomp_prob;
      } else {
        advs_entry_only_uncomp_prob *= uncomp_prob;
      }

      g_queue_push_tail(vlink_out->adversary_str_parts, adv_out);
    }

    g_queue_push_tail(vlink_in->adversary_str_parts, adv_in);
  }

//for exit_adv in exit_advs:
  outqlen = vlink_out ? g_queue_get_length(vlink_out->adversary_str_parts) : 0;
  for(i = 0; i < outqlen; i++) {
    char* adv_out = g_queue_pop_head(vlink_out->adversary_str_parts);

//    if (len(exit_adv) >= 3) and (exit_adv[0:3] == 'as-'):
//        uncomp_prob_adv = TheMan.as_org_uncomp_prob
//    elif (len(exit_adv) >= 4) and (exit_adv[0:4] == 'ixp-'):
//        uncomp_prob_adv = TheMan.ixp_org_uncomp_prob
//    else:
//        logger.info('Unrecognized adversary: {}'.format(entry_adv))
//        continue
    double uncomp_prob = 0.0;
    if(adv_out && g_str_has_prefix(adv_out, "as-")) {
      uncomp_prob = get_options()->TrustASORGUncompProb; //TheMan.as_org_uncomp_prob
    } else if(adv_out && g_str_has_prefix(adv_out, "ixp-")) {
      uncomp_prob = get_options()->TrustIXPORGUncompProb; //TheMan.ixp_org_uncomp_prob
    } else {
      if(adv_out) {
        log_warn(LD_CIRC, "trustdb: unrecognized adversary: %s", adv_out);
        g_free(adv_out);
      }
      continue;
    }

//    if exit_adv not in entry_advs:
//        advs_exit_only_uncomp_prob *= uncomp_prob_adv
    inqlen = vlink_in ? g_queue_get_length(vlink_in->adversary_str_parts) : 0;
    for(j = 0; j < inqlen; j++) {
      char* adv_in = g_queue_pop_head(vlink_in->adversary_str_parts);

      if(adv_in && g_ascii_strcasecmp(adv_in, adv_out)) {
        advs_exit_only_uncomp_prob *= uncomp_prob;
      }

      g_queue_push_tail(vlink_in->adversary_str_parts, adv_in);
    }

    g_queue_push_tail(vlink_out->adversary_str_parts, adv_out);
  }

//uncomp_prob = relay_uncomp_prob * advs_in_both_uncomp_prob *\
//    (advs_entry_only_uncomp_prob + \
//    (1-advs_entry_only_uncomp_prob)*advs_exit_only_uncomp_prob)
  double total_uncomp_prob = relay_uncomp_prob * advs_in_both_uncomp_prob *
      (advs_entry_only_uncomp_prob + ((1-advs_entry_only_uncomp_prob) * advs_exit_only_uncomp_prob));

  return total_uncomp_prob;
}

/*********************************************************************
 * public functions below this point
 */

/* thread private structs from shadow-plugin-tor preload */
gpointer shadow_get_private_trustdb() {
  tor_assert(0 && "must be intercepted and handled by shadow");
  return NULL;
}

void shadow_set_private_trustdb(gpointer tdb) {
  tor_assert(0 && "must be intercepted and handled by shadow");
}

void trustdb_free(trustdb_t* tdb) {
  if(tdb) {
    if(tdb->internal) {
      tdb->internal->refcount--;
      if(tdb->internal->refcount <= 1) {
        /* only the tls key has a reference, so we can destroy */
        if(tdb->internal->src_cluster_ids) {
          g_hash_table_destroy(tdb->internal->src_cluster_ids);
        }
        if(tdb->internal->dst_cluster_ids) {
          g_hash_table_destroy(tdb->internal->dst_cluster_ids);
        }
        if(tdb->internal->guard_ids) {
          g_hash_table_destroy(tdb->internal->guard_ids);
        }
        if(tdb->internal->exit_ids) {
          g_hash_table_destroy(tdb->internal->exit_ids);
        }
        if(tdb->internal->src_clusters) {
          g_hash_table_destroy(tdb->internal->src_clusters);
        }
        if(tdb->internal->dst_clusters) {
          g_hash_table_destroy(tdb->internal->dst_clusters);
        }
        if(tdb->internal->adv_codes) {
          g_hash_table_destroy(tdb->internal->adv_codes);
        }
        g_free(tdb->internal);
        shadow_set_private_trustdb(NULL);
      }
    }
    if(tdb->cc) {
      g_free(tdb->cc);
    }
    g_free(tdb);
  }
}

trustdb_t* trustdb_new(in_addr_t mynetip, unsigned int asn, char* cc, const char* clientsf,
    const char* guardsf, const char* exitsf, const char* serversf,
    const char* scoresf, const char* advsinf, const char* advsoutf, const char* countryf) {
  /* trustlib is node-specific, trustlib internal is thread-specific */
  trustdb_t* tdb = g_new0(trustdb_t, 1);
  tdb->cc = cc;
  tdb->asn = asn;
  tdb->ip = mynetip;

  /* get a pointer to the thread storage */
  trustdb_internal_t* internal = shadow_get_private_trustdb();

  /* initialize it if dne, each thread will store a copy of the trust 'database' info */
  if(!internal) {
    internal = g_new0(trustdb_internal_t, 1);

    internal->src_cluster_ids = _trustdb_parse_clients(clientsf);
    internal->dst_cluster_ids = _trustdb_parse_servers(serversf);
    internal->guard_ids = _trustdb_parse_guards(guardsf);
    internal->exit_ids = _trustdb_parse_exits(exitsf);

    internal->src_clusters = _trust_parse_adversaries_in(advsinf);
    internal->dst_clusters = _trust_parse_adversaries_out(advsoutf);

    if(countryf) {
      internal->adv_codes = _trust_parse_countries(countryf);

      /* count number of unique codes */
      GHashTable* countries = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
      GList* codes = g_hash_table_get_values(internal->adv_codes);
      while(codes != NULL) {
        g_hash_table_replace(countries, codes->data, NULL);
        codes = g_list_next(codes);
      }
      g_list_free(codes);
      internal->num_countries = g_hash_table_size(countries);
      g_hash_table_destroy(countries);
    }

    _trust_parse_guard_scores(internal->src_clusters, scoresf);

    shadow_set_private_trustdb(internal);
    internal->refcount = 1;
  }

  g_assert(internal);
  tdb->internal = internal;
  tdb->internal->refcount++;

  return tdb;
}

double trustdb_get_guard_score(trustdb_t* tdb,
    smartlist_t* existing_guards, const node_t* guard_to_score) {
  tor_assert(tdb && tdb->internal);
  if(get_options()->TrustPolicyCountry) {
    return _trust_get_guard_score_country(tdb, existing_guards, guard_to_score);
  } else {
    return _trust_get_guard_score_theman(tdb, existing_guards, guard_to_score);
  }
}

//XXX FIXME cache result of this function for better performance
double trustdb_get_exit_score(trustdb_t* tdb, in_addr_t guard_netip,
    in_addr_t exit_netip, unsigned int dst_asn) {
  tor_assert(tdb && tdb->internal);
  if(get_options()->TrustPolicyCountry) {
    return _trust_get_exit_score_country(tdb, guard_netip, exit_netip, dst_asn);
  } else {
    return _trust_get_exit_score_theman(tdb, guard_netip, exit_netip, dst_asn);
  }
}
