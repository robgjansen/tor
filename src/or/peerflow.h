/*
 * peerflow.h
 *
 *  Created on: Oct 15, 2014
 *      Author: rob
 */

#ifndef PEERFLOW_H_
#define PEERFLOW_H_

typedef enum _PeerFlowSide {
  PFS_NONE, PFS_CLIENT, PFS_DESTINATION,
} PeerFlowSide;

typedef enum _PeerFlowPosition {
  PFP_NONE, PFP_GUARD, PFP_MIDDLE, PFP_EXIT,
} PeerFlowPosition;

typedef struct peerflow_report_s peerflow_report_t;

peerflow_report_t* peerflow_report_new(const char* id_digest);
void peerflow_report_free(peerflow_report_t* report);
void peerflow_report_add_bytes(peerflow_report_t* report, size_t bytes_received,
    size_t bytes_sent, PeerFlowPosition position, PeerFlowSide side);
unsigned long peerflow_report_get_traffic_estimate(peerflow_report_t* report,
    double g_prob, double m_prob, double e_prob);
void peerflow_reports_obfuscate(digestmap_t* reports, unsigned int* seed_state, double laplace_scale);
char* peerflow_reports_to_string(digestmap_t* reports, const char* header);
digestmap_t* peerflow_reports_from_string(char* reports_str_without_header);

void peerflow_relay_check_free();
void peerflow_relay_check_report();
void peerflow_relay_notify_bytes_observed(connection_t *conn,
    size_t bytes_received, size_t bytes_sent);
void peerflow_relay_notify_cell_received(channel_t* chan, circuit_t* circ);
void peerflow_relay_notify_cell_sent(channel_t* chan, circuit_t* circ);


void peerflow_auth_check_free();
int peerflow_auth_notify_report_received(const char *report_body, const char **msg_out, int *status_out);
void peerflow_auth_process_measurements_for_consensus(smartlist_t *routerstatuses);

#endif /* PEERFLOW_H_ */
