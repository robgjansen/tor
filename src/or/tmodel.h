/*
 * tmodel.h
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#ifndef SRC_OR_TMODEL_H_
#define SRC_OR_TMODEL_H_

#include <stdint.h>

#include "compat_time.h"

typedef enum tmodel_obs_type_e tmodel_obs_type_t;
enum tmodel_obs_type_e {
  TMODEL_OBSTYPE_NONE,
  TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN,
  TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN,
  TMODEL_OBSTYPE_PACKETS_FINISHED,
  TMODEL_OBSTYPE_STREAM,
  TMODEL_OBSTYPE_STREAMS_FINISHED,
  /* if we add another element, we need to increase the amount used
  to store this type in the obs bitfield in tmodel_delay_t */
};

/* An opaque structure representing traffic model info for packets
 * on a stream. The internals of this structure are not intended
 * to be accessed outside of the tmodel class. */
typedef struct tmodel_packets_s tmodel_packets_t;

/* for tracking packets on a stream */
tmodel_packets_t* tmodel_packets_new(void);
void tmodel_packets_free(tmodel_packets_t* tpackets);
/* notify the traffic model of a packet model observation. */
void tmodel_packets_observation(tmodel_packets_t* tpackets,
    tmodel_obs_type_t otype, size_t payload_length);

/* An opaque structure representing traffic model info for streams
 * on a circuit. The internals of this structure are not intended
 * to be accessed outside of the tmodel class. */
typedef struct tmodel_streams_s tmodel_streams_t;

/* for tracking streams on a circuit */
tmodel_streams_t* tmodel_streams_new(void);
void tmodel_streams_free(tmodel_streams_t* tstreams);
/* notify the stream model of a stream model observation. */
void tmodel_streams_observation(tmodel_streams_t* tstreams,
    tmodel_obs_type_t otype, monotime_t stream_obs_time);

int tmodel_set_traffic_model(uint32_t len, const char *body);
int tmodel_is_active(void);

#endif /* SRC_OR_TMODEL_H_ */
