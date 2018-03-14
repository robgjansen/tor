/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.h
 * \brief Header file for control.c.
 **/

#ifndef TOR_CONTROL_H
#define TOR_CONTROL_H

void control_initialize_event_queue(void);

void control_update_global_event_mask(void);
void control_adjust_event_log_severity(void);

void control_ports_write_to_file(void);

/** Log information about the connection <b>conn</b>, protecting it as with
 * CONN_LOG_PROTECT. Example:
 *
 * LOG_FN_CONN(conn, (LOG_DEBUG, "Socket %d wants to write", conn->s));
 **/
#define LOG_FN_CONN(conn, args)                 \
  CONN_LOG_PROTECT(conn, log_fn args)

int connection_control_finished_flushing(control_connection_t *conn);
int connection_control_reached_eof(control_connection_t *conn);
void connection_control_closed(control_connection_t *conn);

int connection_control_process_inbuf(control_connection_t *conn);

#define EVENT_NS 0x000F
int control_event_is_interesting(int event);

int control_event_circuit_status(origin_circuit_t *circ,
                                 circuit_status_event_t e, int reason);
int control_event_circuit_purpose_changed(origin_circuit_t *circ,
                                          int old_purpose);
int control_event_circuit_cannibalized(origin_circuit_t *circ,
                                       int old_purpose,
                                       const struct timeval *old_tv_created);
int control_event_stream_status(entry_connection_t *conn,
                                stream_status_event_t e,
                                int reason);
int control_event_or_conn_status(or_connection_t *conn,
                                 or_conn_status_event_t e, int reason);
int control_event_bandwidth_used(uint32_t n_read, uint32_t n_written);
int control_event_stream_bandwidth(edge_connection_t *edge_conn);
int control_event_stream_bandwidth_used(void);
int control_event_circ_bandwidth_used(void);
int control_event_conn_bandwidth(connection_t *conn);
int control_event_conn_bandwidth_used(void);
int control_event_circuit_cell_stats(void);
int control_event_tb_empty(const char *bucket, uint32_t read_empty_time,
                           uint32_t write_empty_time,
                           int milliseconds_elapsed);
void control_event_logmsg(int severity, uint32_t domain, const char *msg);
int control_event_descriptors_changed(smartlist_t *routers);
int control_event_address_mapped(const char *from, const char *to,
                                 time_t expires, const char *error,
                                 const int cached);
int control_event_my_descriptor_changed(void);
int control_event_network_liveness_update(int liveness);
int control_event_networkstatus_changed(smartlist_t *statuses);

int control_event_newconsensus(const networkstatus_t *consensus);
int control_event_networkstatus_changed_single(const routerstatus_t *rs);
int control_event_general_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_client_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_server_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);

int control_event_general_error(const char *format, ...)
  CHECK_PRINTF(1,2);
int control_event_client_error(const char *format, ...)
  CHECK_PRINTF(1,2);
int control_event_server_error(const char *format, ...)
  CHECK_PRINTF(1,2);

int control_event_guard(const char *nickname, const char *digest,
                        const char *status);
int control_event_conf_changed(const smartlist_t *elements);
int control_event_buildtimeout_set(buildtimeout_set_event_t type,
                                   const char *args);
int control_event_signal(uintptr_t signal);

int init_control_cookie_authentication(int enabled);
char *get_controller_cookie_file_name(void);
smartlist_t *decode_hashed_passwords(config_line_t *passwords);
void disable_control_logging(void);
void enable_control_logging(void);

void monitor_owning_controller_process(const char *process_spec);

int control_event_bootstrap(bootstrap_status_t status, int progress);
MOCK_DECL(void, control_event_bootstrap_prob_or,(const char *warn,
                                                 int reason,
                                                 or_connection_t *or_conn));
void control_event_bootstrap_problem(const char *warn, const char *reason,
                                     const connection_t *conn, int dowarn);

void control_event_clients_seen(const char *controller_str);
void control_event_transport_launched(const char *mode,
                                      const char *transport_name,
                                      tor_addr_t *addr, uint16_t port);
const char *rend_auth_type_to_string(rend_auth_type_t auth_type);
MOCK_DECL(const char *, node_describe_longname_by_id,(const char *id_digest));
void control_event_hs_descriptor_requested(const rend_data_t *rend_query,
                                           const char *desc_id_base32,
                                           const char *hs_dir);
void control_event_hs_descriptor_created(const char *service_id,
                                         const char *desc_id_base32,
                                         int replica);
void control_event_hs_descriptor_upload(const char *service_id,
                                        const char *desc_id_base32,
                                        const char *hs_dir);
void control_event_hs_descriptor_receive_end(const char *action,
                                             const char *onion_address,
                                             const rend_data_t *rend_data,
                                             const char *id_digest,
                                             const char *reason);
void control_event_hs_descriptor_upload_end(const char *action,
                                            const char *onion_address,
                                            const char *hs_dir,
                                            const char *reason);
void control_event_hs_descriptor_received(const char *onion_address,
                                          const rend_data_t *rend_data,
                                          const char *id_digest);
void control_event_hs_descriptor_uploaded(const char *hs_dir,
                                          const char *onion_address);
void control_event_hs_descriptor_failed(const rend_data_t *rend_data,
                                        const char *id_digest,
                                        const char *reason);
void control_event_hs_descriptor_upload_failed(const char *hs_dir,
                                               const char *onion_address,
                                               const char *reason);
void control_event_hs_descriptor_content(const char *onion_address,
                                         const char *desc_id,
                                         const char *hsdir_fp,
                                         const char *content);

const char *privcount_get_version_str(void);
char *privcount_timeval_to_iso_epoch_str_dup(const struct timeval *tv);

void privcount_mark_circuit_hsdir_conn(const dir_connection_t *dirconn,
                                       int hs_version_number, int is_store);

int privcount_circuit_used_legacy_handshake(const or_circuit_t *orcirc);
void privcount_set_intro_client_sink(or_circuit_t *client_orcirc,
                                     or_circuit_t *service_orcirc,
                                     int hs_version_number);
void privcount_clear_intro_client_sink(or_circuit_t *orcirc);

void privcount_byte_transfer(connection_t *conn,
                             uint64_t byte_count,
                             int is_outbound,
                             int is_legacy_count);
void privcount_cell_transfer(circuit_t *circ,
                             const channel_t *chan,
                             int is_sent,
                             int is_legacy_count);

/* Positional events */
void control_event_privcount_dns_resolved(const edge_connection_t *exitconn,
                                          const or_circuit_t *orcirc);
void control_event_privcount_stream_bytes_transferred(
                                            const edge_connection_t *exitconn,
                                            const or_circuit_t *orcirc,
                                            uint64_t amt, int is_outbound);
void control_event_privcount_stream_ended(const edge_connection_t *exitconn);
void control_event_privcount_connection(const or_connection_t *orconn);
/* Tagged events */
MOCK_DECL(void, control_event_privcount_viterbi_packets,(char* viterbi_result));
MOCK_DECL(void, control_event_privcount_viterbi_streams,(char* viterbi_result));
/* Forward declaration to avoid including hs_cache.h */
typedef struct hs_cache_dir_descriptor_t hs_cache_dir_descriptor_t;
void control_event_privcount_hsdir_cache_store(
                                    int hs_version_number,
                                    int has_existing_cache_entry_flag,
                                    int was_added_to_cache_flag,
                                    const char *cache_reason_string,
                                    const char *desc_id_base32,
                                    const rend_service_descriptor_t *hsv2_desc,
                                    const char *hsv2_desc_body,
                                    const hs_cache_dir_descriptor_t *hsv3_desc,
                                    ssize_t encoded_descriptor_byte_count,
                                    ssize_t encoded_intro_point_byte_count);
void control_event_privcount_hsdir_cache_fetch(
                            int hs_version_number,
                            int has_cache_entry_flag,
                            ssize_t cache_query_byte_count,
                            const char *cache_reason_string,
                            const char *desc_id_base32,
                            const rend_service_descriptor_t *hsv2_desc,
                            const char *hsv2_desc_body,
                            time_t hsv2_last_served_time,
                            const char *blinded_pubkey_base64,
                            const hs_cache_dir_descriptor_t *hsv3_desc,
                            time_t hsv3_cache_created_time,
                            ssize_t encoded_descriptor_byte_count,
                            ssize_t encoded_intro_point_byte_count);
void control_event_privcount_circuit(circuit_t *circ,
                                     int is_legacy_circuit_end);
void control_event_privcount_circuit_cell(
                                        const channel_t *chan,
                                        circuit_t *circ,
                                        const cell_t *cell,
                                        int is_sent,
                                        const int *is_recognized,
                                        const int *was_relay_crypt_successful,
                                        relay_header_t* precrypt_relay_header);
#define PRIVCOUNT_CELL_RECEIVED 0
#define PRIVCOUNT_CELL_SENT 1

void queued_events_flush_all(int force);
void control_free_all(void);

#ifdef CONTROL_PRIVATE
/* Recognized asynchronous event types.  It's okay to expand this list
 * because it is used both as a list of v0 event types, and as indices
 * into the bitfield to determine which controllers want which events.
 */
/* This bitfield has no event zero    0x0000 */
#define EVENT_MIN_                    0x0001
#define EVENT_CIRCUIT_STATUS          0x0001
#define EVENT_STREAM_STATUS           0x0002
#define EVENT_OR_CONN_STATUS          0x0003
#define EVENT_BANDWIDTH_USED          0x0004
#define EVENT_CIRCUIT_STATUS_MINOR    0x0005
#define EVENT_NEW_DESC                0x0006
#define EVENT_DEBUG_MSG               0x0007
#define EVENT_INFO_MSG                0x0008
#define EVENT_NOTICE_MSG              0x0009
#define EVENT_WARN_MSG                0x000A
#define EVENT_ERR_MSG                 0x000B
#define EVENT_ADDRMAP                 0x000C
/* There was an AUTHDIR_NEWDESCS event, but it no longer exists.  We
   can reclaim 0x000D. */
#define EVENT_DESCCHANGED             0x000E
/* Exposed above */
// #define EVENT_NS                   0x000F
#define EVENT_STATUS_CLIENT           0x0010
#define EVENT_STATUS_SERVER           0x0011
#define EVENT_STATUS_GENERAL          0x0012
#define EVENT_GUARD                   0x0013
#define EVENT_STREAM_BANDWIDTH_USED   0x0014
#define EVENT_CLIENTS_SEEN            0x0015
#define EVENT_NEWCONSENSUS            0x0016
#define EVENT_BUILDTIMEOUT_SET        0x0017
#define EVENT_GOT_SIGNAL              0x0018
#define EVENT_CONF_CHANGED            0x0019
#define EVENT_CONN_BW                 0x001A
#define EVENT_CELL_STATS              0x001B
#define EVENT_TB_EMPTY                0x001C
#define EVENT_CIRC_BANDWIDTH_USED     0x001D
#define EVENT_TRANSPORT_LAUNCHED      0x0020
#define EVENT_HS_DESC                 0x0021
#define EVENT_HS_DESC_CONTENT         0x0022
#define EVENT_NETWORK_LIVENESS        0x0023
/* These events are in positional format */
/* These events are exit events */
#define EVENT_PRIVCOUNT_DNS_RESOLVED                0x0024
/* These events are position-independent events,
 * but they ignore BEGINDIR, and only report exit cell and byte counts */
#define EVENT_PRIVCOUNT_STREAM_BYTES_TRANSFERRED    0x0025
#define EVENT_PRIVCOUNT_STREAM_ENDED                0x0026
#define EVENT_PRIVCOUNT_CIRCUIT_ENDED               0x0027
#define EVENT_PRIVCOUNT_CONNECTION_ENDED            0x0028
/* These events are in tagged format */
/* These events are HSDir events */
#define EVENT_PRIVCOUNT_HSDIR_CACHE_STORE           0x0029
#define EVENT_PRIVCOUNT_HSDIR_CACHE_FETCH           0x002A
/*
 * #define EVENT_PRIVCOUNT_HSDIR_CACHE_EVICT        0x002B
 */
/* These events are position-independent events.
 * There is no filtering on the Tor side.
 * They include multiple byte and cell counters. */
/*
 * #define EVENT_PRIVCOUNT_STREAM_BYTE              0x0030
 * #define EVENT_PRIVCOUNT_STREAM_CLOSE             0x0031
 */
#define EVENT_PRIVCOUNT_CIRCUIT_CELL                0x0032
#define EVENT_PRIVCOUNT_CIRCUIT_CLOSE               0x0033
#define EVENT_PRIVCOUNT_CONNECTION_CLOSE            0x0034
#define EVENT_PRIVCOUNT_VITERBI_PACKETS             0x0035
#define EVENT_PRIVCOUNT_VITERBI_STREAMS             0x0036

#define EVENT_MAX_                                  0x0036

/* sizeof(control_connection_t.event_mask) in bits, currently a uint64_t */
#define EVENT_CAPACITY_               0x0040

/* If EVENT_MAX_ ever hits 0x0040, we need to make the mask into a
 * different structure, as it can only handle a maximum left shift of 1<<63. */

#if EVENT_MAX_ >= EVENT_CAPACITY_
#error control_connection_t.event_mask has an event greater than its capacity
#endif

#define EVENT_MASK_(e)               (((uint64_t)1)<<(e))

#define EVENT_MASK_NONE_             ((uint64_t)0x0)

#define EVENT_MASK_ABOVE_MIN_        ((~((uint64_t)0x0)) << EVENT_MIN_)
#define EVENT_MASK_BELOW_MAX_        ((~((uint64_t)0x0)) \
                                      >> (EVENT_CAPACITY_ - EVENT_MAX_ \
                                          - EVENT_MIN_))

#define EVENT_MASK_ALL_              (EVENT_MASK_ABOVE_MIN_ \
                                      & EVENT_MASK_BELOW_MAX_)

/* Used only by control.c and test.c */
STATIC size_t write_escaped_data(const char *data, size_t len, char **out);
STATIC size_t read_escaped_data(const char *data, size_t len, char **out);

#ifdef TOR_UNIT_TESTS
MOCK_DECL(STATIC void,
          send_control_event_string,(uint16_t event, const char *msg));

MOCK_DECL(STATIC void,
          queue_control_event_string,(uint16_t event, char *msg));

void control_testing_set_global_event_mask(uint64_t mask);
#endif /* defined(TOR_UNIT_TESTS) */

/** Helper structure: temporarily stores cell statistics for a circuit. */
typedef struct cell_stats_t {
  /** Number of cells added in app-ward direction by command. */
  uint64_t added_cells_appward[CELL_COMMAND_MAX_ + 1];
  /** Number of cells added in exit-ward direction by command. */
  uint64_t added_cells_exitward[CELL_COMMAND_MAX_ + 1];
  /** Number of cells removed in app-ward direction by command. */
  uint64_t removed_cells_appward[CELL_COMMAND_MAX_ + 1];
  /** Number of cells removed in exit-ward direction by command. */
  uint64_t removed_cells_exitward[CELL_COMMAND_MAX_ + 1];
  /** Total waiting time of cells in app-ward direction by command. */
  uint64_t total_time_appward[CELL_COMMAND_MAX_ + 1];
  /** Total waiting time of cells in exit-ward direction by command. */
  uint64_t total_time_exitward[CELL_COMMAND_MAX_ + 1];
} cell_stats_t;
void sum_up_cell_stats_by_command(circuit_t *circ,
                                  cell_stats_t *cell_stats);
void append_cell_stats_by_command(smartlist_t *event_parts,
                                  const char *key,
                                  const uint64_t *include_if_non_zero,
                                  const uint64_t *number_to_include);
void format_cell_stats(char **event_string, circuit_t *circ,
                       cell_stats_t *cell_stats);
STATIC char *get_bw_samples(void);

STATIC crypto_pk_t *add_onion_helper_keyarg(const char *arg, int discard_pk,
                                            const char **key_new_alg_out,
                                            char **key_new_blob_out,
                                            char **err_msg_out);
STATIC rend_authorized_client_t *
add_onion_helper_clientauth(const char *arg, int *created, char **err_msg_out);

STATIC int getinfo_helper_onions(
    control_connection_t *control_conn,
    const char *question,
    char **answer,
    const char **errmsg);
STATIC void getinfo_helper_downloads_networkstatus(
    const char *flavor,
    download_status_t **dl_to_emit,
    const char **errmsg);
STATIC void getinfo_helper_downloads_cert(
    const char *fp_sk_req,
    download_status_t **dl_to_emit,
    smartlist_t **digest_list,
    const char **errmsg);
STATIC void getinfo_helper_downloads_desc(
    const char *desc_req,
    download_status_t **dl_to_emit,
    smartlist_t **digest_list,
    const char **errmsg);
STATIC void getinfo_helper_downloads_bridge(
    const char *bridge_req,
    download_status_t **dl_to_emit,
    smartlist_t **digest_list,
    const char **errmsg);
STATIC int getinfo_helper_downloads(
    control_connection_t *control_conn,
    const char *question, char **answer,
    const char **errmsg);
STATIC int getinfo_helper_dir(
    control_connection_t *control_conn,
    const char *question, char **answer,
    const char **errmsg);

#endif /* defined(CONTROL_PRIVATE) */

#endif /* !defined(TOR_CONTROL_H) */

