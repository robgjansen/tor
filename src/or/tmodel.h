/*
 * tmodel.h
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#ifndef SRC_OR_TMODEL_H_
#define SRC_OR_TMODEL_H_

#include <stdint.h>

/* returns 0 if the traffic model body is parsed correctly and
 * the traffic model is loaded and ready to run viterbi on
 * closed streams. returns 1 if there is an error. */
int tmodel_set_traffic_model(uint32_t len, char *body);

#endif /* SRC_OR_TMODEL_H_ */
