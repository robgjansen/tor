/*
 * tmodel.h
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#ifndef SRC_OR_TMODEL_H_
#define SRC_OR_TMODEL_H_

#include <stdint.h>

typedef enum tmodel_action_e tmodel_action_t;
enum tmodel_action_e {
    TMODEL_OBS_NONE,
    TMODEL_OBS_SENT_TO_ORIGIN,
    TMODEL_OBS_RECV_FROM_ORIGIN,
    TMODEL_OBS_DONE,
};

/* An opaque structure representing traffic model info for packets
 * on a stream. The internals of this structure are not intended
 * to be accessed outside of the tmodel class. */
typedef struct tmodel_packets_s tmodel_packets_t;

tmodel_packets_t* tmodel_packets_new(void);
void tmodel_packets_cell_transferred(tmodel_packets_t* tpackets, size_t length, tmodel_action_t obs);
void tmodel_packets_free(tmodel_packets_t* tpackets);

int tmodel_set_traffic_model(uint32_t len, const char *body);
int tmodel_is_active(void);

#endif /* SRC_OR_TMODEL_H_ */
