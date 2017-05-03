/*
 * trust.h
 *
 *  Created on: Apr 28, 2014
 *      Author: rob
 */

#ifndef TRUST_H_
#define TRUST_H_

#include "or.h"

typedef struct trustdb_s trustdb_t;

trustdb_t* trustdb_new(in_addr_t mynetip, unsigned int asn, char* cc, const char* clientsf,
    const char* guardsf, const char* exitsf, const char* serversf,
    const char* scoresf, const char* advsinf, const char* advsoutf, const char* countryf);
void trustdb_free(trustdb_t* tdb);

double trustdb_get_guard_score(trustdb_t* tdb,
    smartlist_t* existing_guards, const node_t* guard_to_score);
double trustdb_get_exit_score(trustdb_t* tdb, in_addr_t guard_netip,
    in_addr_t exit_netip, unsigned int dst_asn);


void trust_init();
void trust_free();
int trust_get_asn(in_addr_t ip, int* asnout); // intercepted by shadow
int trust_get_cc(in_addr_t ip, char* ccout); // intercepted by shadow
int trust_needs_trust(uint8_t purpose, int flags);
int trust_circuit_is_ok_for_dest(const entry_connection_t *conn,
                             const origin_circuit_t *circ);
int trust_choose_cpath(const entry_connection_t *conn, origin_circuit_t *circ);

#endif /* TRUST_H_ */
