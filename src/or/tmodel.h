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

/* An opaque structure representing stream model info. The internals
 * of this structure are not intended to be accessed outside of the
 * tmodel class. */
typedef struct tmodel_stream_s tmodel_stream_t;

tmodel_stream_t* tmodel_stream_new(void);
void tmodel_stream_cell_transferred(tmodel_stream_t* tstream, size_t length, tmodel_action_t obs);
void tmodel_stream_free(tmodel_stream_t* tstream);

int tmodel_set_traffic_model(uint32_t len, char *body);
int tmodel_is_active(void);

#endif /* SRC_OR_TMODEL_H_ */
