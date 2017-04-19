/*
 * peerflow_report.c
 *
 *  Created on: Oct 23, 2014
 *      Author: rob
 */

#include <math.h>

#include "or.h"
#include "peerflow.h"
#include "router.h"
#include "routerlist.h"

typedef struct peerflow_observation_s {
  size_t bytes_sent;
  size_t bytes_received;
} peerflow_observation_t;

struct peerflow_report_s {
  char peer_id_digest[DIGEST_LEN];
  peerflow_observation_t total;
  peerflow_observation_t gc;
  peerflow_observation_t mc;
  peerflow_observation_t md;
  peerflow_observation_t ed;
  uint32_t magic;
};

#define PEERFLOW_REPORT_MAGIC 0x91DC39F0u

peerflow_report_t* peerflow_report_new(const char* id_digest) {
  tor_assert(id_digest);

  peerflow_report_t* peer_report = tor_malloc_zero(sizeof(struct peerflow_report_s));
  peer_report->magic = PEERFLOW_REPORT_MAGIC;
  memcpy(peer_report->peer_id_digest, id_digest, DIGEST_LEN);

  return peer_report;
}

void peerflow_report_free(peerflow_report_t* report) {
  tor_assert(report->magic == PEERFLOW_REPORT_MAGIC);
  report->magic = 0;
  tor_free(report);
}

void peerflow_report_add_bytes(peerflow_report_t* report, size_t bytes_received,
    size_t bytes_sent, PeerFlowPosition position, PeerFlowSide side) {
  tor_assert(report->magic == PEERFLOW_REPORT_MAGIC);

  if(side == PFS_CLIENT && position == PFP_GUARD) {
    report->gc.bytes_received += bytes_received;
    report->gc.bytes_sent += bytes_sent;
  } else if(side == PFS_CLIENT && position == PFP_MIDDLE) {
    report->mc.bytes_received += bytes_received;
    report->mc.bytes_sent += bytes_sent;
  } else if(side == PFS_DESTINATION && position == PFP_MIDDLE) {
    report->md.bytes_received += bytes_received;
    report->md.bytes_sent += bytes_sent;
  } else if(side == PFS_DESTINATION && position == PFP_EXIT) {
    report->ed.bytes_received += bytes_received;
    report->ed.bytes_sent += bytes_sent;
  } else if(side == PFS_NONE && position == PFP_NONE) {
    report->total.bytes_received += bytes_received;
    report->total.bytes_sent += bytes_sent;
  } else {
    log_err(LD_ACCT, "incorrect side %i position %i",
        (int)side, (int)position);
    tor_assert(0);
  }
}

static size_t _peerflow_report_make_noisy_laplace(unsigned int* seed_state, size_t val, double scale) {
  double location = (double)val;
  double r = ((double)(((double)rand_r(seed_state)) / ((double)RAND_MAX))) - 0.5f;
  double r_sign = r > 0 ? 1.0f : r < 0 ? -1.0f : 0.0f;
  double noise = location - (scale * r_sign)*(log(1.0f - 2*abs(r)));
  double obfuscated_val = location + noise;
  return (size_t) (obfuscated_val > 0.0f ? obfuscated_val : 0);
}

void peerflow_reports_obfuscate(digestmap_t* reports, unsigned int* seed_state, double laplace_scale) {
  tor_assert(reports);
  tor_assert(digestmap_size(reports) > 0);

  /* append a line for each observed peer on which we report */
  DIGESTMAP_FOREACH(reports, id_key, peerflow_report_t*, report) {
    tor_assert(report->magic == PEERFLOW_REPORT_MAGIC);

    report->total.bytes_received =
        _peerflow_report_make_noisy_laplace(seed_state, report->total.bytes_received, laplace_scale);
    report->total.bytes_sent =
        _peerflow_report_make_noisy_laplace(seed_state, report->total.bytes_sent, laplace_scale);
    report->gc.bytes_received =
        _peerflow_report_make_noisy_laplace(seed_state, report->gc.bytes_received, laplace_scale);
    report->gc.bytes_sent =
        _peerflow_report_make_noisy_laplace(seed_state, report->gc.bytes_sent, laplace_scale);
    report->mc.bytes_received =
        _peerflow_report_make_noisy_laplace(seed_state, report->mc.bytes_received, laplace_scale);
    report->mc.bytes_sent =
        _peerflow_report_make_noisy_laplace(seed_state, report->mc.bytes_sent, laplace_scale);
    report->md.bytes_received =
        _peerflow_report_make_noisy_laplace(seed_state, report->md.bytes_received, laplace_scale);
    report->md.bytes_sent =
        _peerflow_report_make_noisy_laplace(seed_state, report->md.bytes_sent, laplace_scale);
    report->ed.bytes_received =
        _peerflow_report_make_noisy_laplace(seed_state, report->ed.bytes_received, laplace_scale);
    report->ed.bytes_sent =
        _peerflow_report_make_noisy_laplace(seed_state, report->ed.bytes_sent, laplace_scale);
  } DIGESTMAP_FOREACH_END;
}

char* peerflow_reports_to_string(digestmap_t* reports, const char* header) {
  tor_assert(reports);
  tor_assert(header);
  tor_assert(digestmap_size(reports) > 0);

  /* start with the report header for the reporting peer */
  char* report_msg = NULL;
  tor_asprintf(&report_msg, "%s;", header);

  /* append a line for each observed peer on which we report */
  DIGESTMAP_FOREACH(reports, id_key, peerflow_report_t*, report) {
    tor_assert(report->magic == PEERFLOW_REPORT_MAGIC);

    const routerinfo_t* ri = router_get_by_id_digest(report->peer_id_digest);
    char id_hex[HEX_DIGEST_LEN+1];
    memset(id_hex, 0, HEX_DIGEST_LEN+1);
    base16_encode(id_hex, HEX_DIGEST_LEN+1, ri->cache_info.identity_digest, DIGEST_LEN);

    char* new_msg = NULL;
    tor_asprintf(&new_msg,
        "%s%s %s total %lu %lu gc %lu %lu mc %lu %lu md %lu %lu ed %lu %lu;",
        report_msg, id_hex, ri ? ri->nickname : "unknown",
        (unsigned long)report->total.bytes_received,
        (unsigned long)report->total.bytes_sent,
        (unsigned long)report->gc.bytes_received,
        (unsigned long)report->gc.bytes_sent,
        (unsigned long)report->mc.bytes_received,
        (unsigned long)report->mc.bytes_sent,
        (unsigned long)report->md.bytes_received,
        (unsigned long)report->md.bytes_sent,
        (unsigned long)report->ed.bytes_received,
        (unsigned long)report->ed.bytes_sent);

    tor_free(report_msg);
    report_msg = new_msg;
  } DIGESTMAP_FOREACH_END;

  return report_msg;
}

static int _peerflow_reports_from_string_helper(char** strtokptr,
    peerflow_report_t* report, PeerFlowPosition position, PeerFlowSide side) {
  char* bytes_received_str = strtok_r(NULL, " ", strtokptr);
  char* bytes_sent_str = bytes_received_str ? strtok_r(NULL, " ", strtokptr) : NULL;

  if(bytes_received_str && bytes_sent_str) {
    peerflow_report_add_bytes(report,
        strtoul(bytes_received_str, NULL, 10),
        strtoul(bytes_sent_str, NULL, 10),
        position, side);
    return 1;
  } else {
    return 0;
  }
}

digestmap_t* peerflow_reports_from_string(char* report_body) {
  int success = 0;
  peerflow_report_t* report = NULL;
  digestmap_t* reports = digestmap_new();

  char* record_ptr = NULL;
  char* record = strtok_r(report_body, ";", &record_ptr);

  while(record) {
    char* ptr = NULL;
    char peer_id_digest[DIGEST_LEN];
    memset(peer_id_digest, 0, DIGEST_LEN);

    char* token = strtok_r(record, " ", &ptr);
    base16_decode(peer_id_digest, DIGEST_LEN, token, strnlen(token, HEX_DIGEST_LEN));

    if(!digestmap_get(reports, peer_id_digest)) {
      report = peerflow_report_new(peer_id_digest);

      strtok_r(NULL, " ", &ptr); // skip nickname
      strtok_r(NULL, " ", &ptr); // skip 'total'
      success = _peerflow_reports_from_string_helper(&ptr, report, PFP_NONE, PFS_NONE);
      if(!success) {
        break;
      }

      strtok_r(NULL, " ", &ptr); // skip 'gc'
      success = _peerflow_reports_from_string_helper(&ptr, report, PFP_GUARD, PFS_CLIENT);
      if(!success) {
        break;
      }

      strtok_r(NULL, " ", &ptr); // skip 'mc'
      success = _peerflow_reports_from_string_helper(&ptr, report, PFP_MIDDLE, PFS_CLIENT);
      if(!success) {
        break;
      }

      strtok_r(NULL, " ", &ptr); // skip 'md'
      success = _peerflow_reports_from_string_helper(&ptr, report, PFP_MIDDLE, PFS_DESTINATION);
      if(!success) {
        break;
      }

      strtok_r(NULL, " ", &ptr); // skip 'ed'
      success = _peerflow_reports_from_string_helper(&ptr, report, PFP_EXIT, PFS_DESTINATION);
      if(!success || strtok_r(NULL, " ", &ptr) != NULL) {
        break;
      }

      /* we think we got everything correctly */
      digestmap_set(reports, peer_id_digest, report);
      report = NULL;
    }

    record = strtok_r(NULL, ";", &record_ptr);
  }

  if(!success) {
    if(report) {
      peerflow_report_free(report);
    }
    digestmap_free(reports, (void (*)(void *))peerflow_report_free);
    reports = NULL;
  }
  return reports;
}

unsigned long peerflow_report_get_traffic_estimate(peerflow_report_t* report,
    double g_prob, double m_prob, double e_prob) {
  tor_assert(report->magic == PEERFLOW_REPORT_MAGIC);

  size_t total_gc = report->gc.bytes_sent + report->gc.bytes_received;
  size_t total_mc = report->mc.bytes_sent + report->mc.bytes_received;
  size_t total_md = report->md.bytes_sent + report->md.bytes_received;
  size_t total_ed = report->ed.bytes_sent + report->ed.bytes_received;

  unsigned long weighted_gc = (unsigned long)(total_gc / g_prob);
  unsigned long weighted_mc = (unsigned long)(total_mc / m_prob);
  unsigned long weighted_md = (unsigned long)(total_md / m_prob);
  unsigned long weighted_ed = (unsigned long)(total_ed / e_prob);

  unsigned long client_side_traffic = weighted_gc + weighted_mc;
  unsigned long destination_side_traffic = weighted_md + weighted_ed;

  return MAX(client_side_traffic, destination_side_traffic);
}
