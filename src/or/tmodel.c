/*
 * tmodel.c
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#include <stdio.h>
#include <stdint.h>
#include <strings.h>

#include "tmodel.h"
#include "or.h"
#include "config.h"
#include "container.h"
#include "control.h"
#include "torlog.h"
#include "util.h"
#include "util_bug.h"

#define TRAFFIC_MODEL_MAGIC 0xAABBCCDD
#define TRAFFIC_STREAM_MAGIC 0xDDCCBBAA

#define TMODEL_MAX_STATE_STR_LEN 63
#define TMODEL_MAX_OBS_STR_LEN 7

/* the approximate number of payload bytes for a packet */
#define TMODEL_PACKET_BYTE_COUNT 1434
/* assume a packet arrived at the same time if it arrived
 * within this many microseconds */
#define TMODEL_PACKET_TIME_TOLERENCE 100

/* default obs names */
/* '+' means a packet was sent away from the client side */
#define TMODEL_OBS_SENT_STR "+"
/* '-' means a packet was sent toward the client side */
#define TMODEL_OBS_RECV_STR "-"
/* 'F' means the stream is ended */
#define TMODEL_OBS_DONE_STR "F"

/* the tmodel_stream internal elements (see tmodel.h for typedef) */
struct tmodel_stream_s {
    /* Time the stream was created */
    monotime_t creation_time;
    monotime_t prev_emit_time;

    /* uncommitted packet info. we hold info until a tolerence
     * so that we can count data that arrives at the same time
     * as part of the same packets. */
    monotime_t buf_emit_time;
    int64_t buf_delay;
    size_t buf_length;
    tmodel_action_t buf_obs;

    /* committed observations */
    smartlist_t* observations;

    /* for memory checking */
    uint magic;
};

/* An opaque structure representing a traffic model. The internals
 * of this structure are not intended to be accessed outside of the
 * tmodel class. */
typedef struct tmodel_s tmodel_t;

/* the tmodel internal elements */
struct tmodel_s {
    /* array of strings holding names of each observation
     * in the observation space */
    char** obs_space;
    /* the number of observations in obs_space.
     * (the length of the obs_space array). */
    uint num_obs;

    /* array of strings holding names of each state
     * in the state space */
    char** state_space;
    /* the number of states in state_space.
     * (the length of the state_space array). */
    uint num_states;

    /* array of size num_states where the start prob of
     * state state_space[i] is held in start_prob[i] */
    double* start_prob;

    /* matrix of size num_states*num_states
     * where the transition prob of src state
     * state_space[i] and dst state state_space[j]
     * is held in trans_prob[i][j] */
    double** trans_prob;

    /* matrices of size num_states*num_obs
     * where the emission value of state
     * state_space[i] and observation obs_space[j]
     * is held in emit_val[i][j] */
    double** emit_dp;
    double** emit_mu;
    double** emit_sigma;

    /* for memory checking */
    uint magic;
};

/* global pointer to traffic model state */
tmodel_t* global_traffic_model = NULL;

/* returns true if we want to know about cells on exit streams,
 * false otherwise. */
int tmodel_is_active(void) {
  if (get_options()->EnablePrivCount && global_traffic_model != NULL &&
      global_traffic_model->magic == TRAFFIC_MODEL_MAGIC) {
    return 1;
  }
  return 0;
}

static int _tmodel_get_state_index(tmodel_t* tmodel, char* state_name) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    for(uint i = 0; i < tmodel->num_states; i++) {
        if(strncasecmp(tmodel->state_space[i], state_name, 63) == 0) {
            return i;
        }
    }

    log_warn(LD_GENERAL, "unable to find state index");
    return -1;
}

static int _tmodel_get_obs_index(tmodel_t* tmodel, char* obs_name) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    for(uint i = 0; i < tmodel->num_obs; i++) {
        if(strncasecmp(tmodel->obs_space[i], obs_name, 7) == 0) {
            return i;
        }
    }

    log_warn(LD_GENERAL, "unable to find obs index");
    return -1;
}

static int _json_find_object_end_pos(const char* json) {
    /* start is the opening bracket or brace */
    char open = json[0];
    char close;
    if (open == '[') {
        close = ']';
    } else if (open == '{') {
        close = '}';
    } else {
        log_warn(LD_GENERAL, "unable to recognize object delimiter");
        return -1;
    }

    /* we start at depth one for the first char */
    int depth = 1;

    /* we need to find when the object closes */
    int i = 1;
    for(i = 1; json[i] != '\0' && depth > 0; i++) {
        if (json[i] == open) {
            depth++;
        } else if (json[i] == close) {
            depth--;
        }
    }

    /* if we found the close, return the position */
    if (depth == 0) {
        return i;
    } else {
        log_warn(LD_GENERAL, "object has incorrect depth");
        return -1;
    }
}

static uint _parse_json_state_space(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;
    uint count = 0;

    while (json[i] != ']' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing state name");
            return -1;
        }

        /* process the state name */
        log_debug(LD_GENERAL, "found state '%s'", state_name);
        if(tmodel) {
            tmodel->state_space[count] = strndup(state_name, 63);
        }
        count++;

        /* fast forward to the end of the name,
         * plus 2 for the quote characters. */
        i += strnlen(state_name, 63) + 2;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return count;
}
static uint _parse_json_obs_space(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;
    uint count = 0;

    while (json[i] != ']' && i <= obj_end_pos) {
        char obs_name[8];
        memset(obs_name, 0, 8);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%7[^\"]", obs_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing obs name");
            return 1;
        }

        /* process the state name */
        log_debug(LD_GENERAL, "found observation '%s'", obs_name);
        if(tmodel) {
            tmodel->obs_space[count] = strndup(obs_name, 7);
        }
        count++;

        /* fast forward to the end of the name,
         * plus 2 for the quote characters. */
        i += strnlen(obs_name, 7) + 2;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return count;
}

static int _parse_json_emit_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing emit state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name, 63) + 3;

        /* we have another dict for dst states */
        int inner_dict_len = _json_find_object_end_pos(&json[i]);
        int inner_obj_end_pos = i + inner_dict_len;

        /* jump one past the start of the inner dict */
        if (json[i] != '{') {
            log_warn(LD_GENERAL, "expected opening brace in emit object");
            return 1;
        } else {
            i++;
        }

        int state_index = _tmodel_get_state_index(tmodel, state_name);
        if(state_index < 0) {
            log_warn(LD_GENERAL, "unable to find state index");
            return 1;
        }

        /* iterate the inner dict object */
        while(json[i] != '}' && i <= inner_obj_end_pos) {
            char obs[8];
            memset(obs, 0, 8);

            n_assigned = sscanf(&json[i], "\"%7[^\"]", obs);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing emit obs name");
                return 1;
            }

            /* fast forward to the end of the dst state name,
             * plus 3 for the quotes and the ':'. */
            i += strnlen(obs, 7) + 3;

            if(json[i] != '[') {
                log_warn(LD_GENERAL, "unable to find emit list start bracket");
                return 1;
            }

            int emit_vals_list_len = _json_find_object_end_pos(&json[i]);
            if (emit_vals_list_len < 0) {
                log_warn(LD_GENERAL, "unable to find emit list len");
                return 1;
            }

            int obs_index = _tmodel_get_obs_index(tmodel, obs);
            if(obs_index < 0) {
                log_warn(LD_GENERAL, "unable to find emit obs index");
                return 1;
            }

            double dp = 0.0, mu = 0.0, sigma = 0.0;
            n_assigned = sscanf(&json[i], "[%lf;%lf;%lf]", &dp, &mu, &sigma);
            if (n_assigned != 3) {
                log_warn(LD_GENERAL, "sscanf problem parsing emit values");
                return 1;
            }

            /* process the items */
            log_debug(LD_GENERAL,
                    "found emit for state '%s' and obs '%s': dp='%f' mu='%f' sigma='%f'",
                    state_name, obs, dp, mu, sigma);

            tmodel->emit_dp[state_index][obs_index] = dp;
            tmodel->emit_mu[state_index][obs_index] = mu;
            tmodel->emit_sigma[state_index][obs_index] = sigma;

            /* fast forward to one past the end of the list */
            i += emit_vals_list_len;

            /* check if we have another element, which is normally
             * separated by a comma, but we separate by a ';'. */
            if(json[i] == ';') {
                i++;
            }
        }

        if(json[i] != '}') {
            log_warn(LD_GENERAL, "unable to find emit closing brace");
            return 1;
        }

        /* jump ahead one, past the end of the inner dict */
        i++;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static int _parse_json_trans_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name_src[64];
        memset(state_name_src, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name_src);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing trans src state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name_src, 63) + 3;

        /* we have another dict for dst states */
        int inner_dict_len = _json_find_object_end_pos(&json[i]);
        int inner_obj_end_pos = i + inner_dict_len;

        /* jump one past the start of the inner dict */
        if (json[i] != '{') {
            log_warn(LD_GENERAL, "unable to find trans open brace");
            return 1;
        } else {
            i++;
        }

        int src_index = _tmodel_get_state_index(tmodel, state_name_src);
        if(src_index < 0) {
            log_warn(LD_GENERAL, "unable to find trans src state index");
            return 1;
        }

        /* iterate the inner dict object */
        while(json[i] != '}' && i <= inner_obj_end_pos) {
            char state_name_dst[64];
            memset(state_name_dst, 0, 64);

            n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name_dst);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing trans dst state name");
                return 1;
            }

            /* fast forward to the end of the dst state name,
             * plus 3 for the quotes and the ':'. */
            i += strnlen(state_name_dst, 63) + 3;

            int dst_index = _tmodel_get_state_index(tmodel, state_name_dst);
            if(dst_index < 0) {
                log_warn(LD_GENERAL, "unable to find trans dst state index");
                return 1;
            }

            double trans_prob = 0.0;
            n_assigned = sscanf(&json[i], "%lf;", &trans_prob);
            if (n_assigned != 1) {
                log_warn(LD_GENERAL, "sscanf problem parsing trans prob val");
                return 1;
            }

            /* process the items */
            log_debug(LD_GENERAL, "found trans from '%s' to '%s' = '%f'",
                    state_name_src, state_name_dst, trans_prob);

            tmodel->trans_prob[src_index][dst_index] = trans_prob;

            /* fast forward to the next entry or the end */
            while(json[i] != ';' && json[i] != '}' && i < inner_obj_end_pos) {
                i++;
            }

            /* check if we have another element, which is normally
             * separated by a comma, but we separate by a ';'. */
            if(json[i] == ';') {
                i++;
            }
        }

        /* jump ahead one, past the end of the inner dict */
        i++;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static int _parse_json_start_prob(const char* json, int obj_end_pos, tmodel_t* tmodel) {
    /* start parsing states 1 past the object open char */
    int i = 1;

    while (json[i] != '}' && i <= obj_end_pos) {
        char state_name[64];
        memset(state_name, 0, 64);

        /* read the state name string. */
        int n_assigned = sscanf(&json[i], "\"%63[^\"]", state_name);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing start state name");
            return 1;
        }

        /* fast forward to the end of the name,
         * plus 3 for the quotes and the ':'. */
        i += strnlen(state_name, 63) + 3;

        int state_index = _tmodel_get_state_index(tmodel, state_name);
        if(state_index < 0) {
            log_warn(LD_GENERAL, "unable to find start state name index");
            return 1;
        }

        double start_prob = 0.0;
        n_assigned = sscanf(&json[i], "%lf;", &start_prob);
        if (n_assigned != 1) {
            log_warn(LD_GENERAL, "sscanf problem parsing start prob");
            return 1;
        }

        /* process the items */
        log_debug(LD_GENERAL, "found state '%s' and start_prob '%f'",
                state_name, start_prob);

        tmodel->start_prob[state_index] = start_prob;

        /* fast forward to the next entry or the end */
        while(json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
            i++;
        }

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

/* we loop twice, once to parse the state space and observation
 * space which is only done if parse_spaces=1. on the second
 * pass, we parse the trans_prob, emit_prob, an start_prob
 * objects, given the space and observation spaces that we
 * parsed in the first step. */
static int _parse_json_objects(const char* json, int parse_spaces, tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    int i = 0, j = 0;
    if (json[i] != '{') {
        return 1;
    } else {
        i++;
    }

    while (json[i] != '}') {
        /* static buffer to hold the parsed type */
        char input_type[32];
        memset(input_type, 0, 32);

        /* read the type. will be one of the following:
         *   '"states"', '"emission_probability"',
         *   'transition_probability', 'start_probability'
         * they may appear in any order.
         */
        int n_assigned = sscanf(&json[i], "\"%30[^\"]", input_type);
        if (n_assigned != 1) {
            return 1;
        }

        /* fast forward to the object starting position,
         * which will be at 1 past the ':' character.
         * add 3 for the "": chars */
        i += strnlen(input_type, 30) + 3;

        /* find the end of the object */
        j = _json_find_object_end_pos(&json[i]);
        if (j < 0) {
            return 1;
        }

        log_info(LD_GENERAL, "found object '%s' of length %d", input_type, j);

        /* handle each object type */
        if (json[i] == '[' &&
                strncasecmp(input_type, "state_space", 6) == 0) {
            if(parse_spaces) {
                /* first count the number of states */
                uint num_states = _parse_json_state_space(&json[i], j, NULL);
                if(num_states <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_state_space failed to count states (1)");
                    return 1;
                }

                /* allocate the state array */
                tmodel->num_states = num_states;
                tmodel->state_space = calloc(tmodel->num_states, sizeof(char*));

                /* now actually store the values by giving a model */
                num_states = _parse_json_state_space(&json[i], j, tmodel);
                if(num_states <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_state_space failed to count states (2)");
                    return 1;
                }
            }
        } else if (json[i] == '[' &&
                strncasecmp(input_type, "observation_space", 17) == 0) {
            if(parse_spaces) {
                /* first count the number of states */
                uint num_obs = _parse_json_obs_space(&json[i], j, NULL);
                if(num_obs <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (1)");
                    return 1;
                }

                /* allocate the obs array */
                tmodel->num_obs = num_obs;
                tmodel->obs_space = calloc(tmodel->num_obs, sizeof(char*));

                /* now actually store the values by giving a model */
                num_obs = _parse_json_obs_space(&json[i], j, tmodel);
                if(num_obs <= 0) {
                    log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (2)");
                    return 1;
                }
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "emission_probability", 20) == 0) {
            if(!parse_spaces && _parse_json_emit_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_emit_prob failed");
                return 1;
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "transition_probability", 22) == 0) {
            if(!parse_spaces && _parse_json_trans_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_trans_prob failed");
                return 1;
            }
        } else if (json[i] == '{' &&
                strncasecmp(input_type, "start_probability", 17) == 0) {
            if(!parse_spaces && _parse_json_start_prob(&json[i], j, tmodel) != 0) {
                log_warn(LD_GENERAL, "_parse_json_start_prob failed");
                return 1;
            }
        } else {
            return 1;
        }

        /* Jump to the end of the object, and add 1 to
         * get the the start of the next item. */
        i += j;

        /* check if we have another element, which is normally
         * separated by a comma, but we separate by a ';'. */
        if(json[i] == ';') {
            i++;
        }
    }

    /* success! */
    return 0;
}

static void _tmodel_log_model(tmodel_t* tmodel) {
  tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

  if (tmodel->state_space) {
    log_info(LD_GENERAL, "Logging tmodel state space");
    for (uint i = 0; i < tmodel->num_states; i++) {
      if (tmodel->state_space[i]) {
        log_info(LD_GENERAL, "found state_space[%i] '%s'", i, tmodel->state_space[i]);
      }
    }
  }

  if (tmodel->obs_space) {
    log_info(LD_GENERAL, "Logging tmodel observation space");
    for (uint i = 0; i < tmodel->num_obs; i++) {
      if (tmodel->obs_space[i]) {
        log_info(LD_GENERAL, "found obs_space[%i] '%s'", i, tmodel->obs_space[i]);
      }
    }
  }

  if (tmodel->start_prob) {
    log_info(LD_GENERAL, "Logging tmodel start probabilities");
    for (uint i = 0; i < tmodel->num_states; i++) {
      log_info(LD_GENERAL, "found start_prob[%i] '%f'", i, tmodel->start_prob[i]);
    }
  }

  if (tmodel->trans_prob) {
    log_info(LD_GENERAL, "Logging tmodel transition probabilities");
    for (uint i = 0; i < tmodel->num_states; i++) {
      if (tmodel->trans_prob[i]) {
        for (uint j = 0; j < tmodel->num_states; j++) {
          log_info(LD_GENERAL, "found trans_prob[%i][%i] '%f'", i, j, tmodel->trans_prob[i][j]);
        }
      }
    }
  }

  if (tmodel->emit_dp && tmodel->emit_mu && tmodel->emit_sigma) {
    log_info(LD_GENERAL, "Logging tmodel emission values");
    for (uint i = 0; i < tmodel->num_states; i++) {
      if (tmodel->emit_dp[i] && tmodel->emit_mu[i] && tmodel->emit_sigma[i]) {
        for (uint j = 0; j < tmodel->num_obs; j++) {
          log_info(LD_GENERAL, "found emit_dp[%i][%i] '%f'", i, j, tmodel->emit_dp[i][j]);
          log_info(LD_GENERAL, "found emit_mu[%i][%i] '%f'", i, j, tmodel->emit_mu[i][j]);
          log_info(LD_GENERAL, "found emit_sigma[%i][%i] '%f'", i, j, tmodel->emit_sigma[i][j]);
        }
      }
    }
  }
}

static void _tmodel_allocate_arrays(tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    tmodel->start_prob = calloc((size_t)tmodel->num_states, sizeof(double));

    tmodel->trans_prob = calloc((size_t)tmodel->num_states, sizeof(double*));
    for(uint i = 0; i < tmodel->num_states; i++) {
        tmodel->trans_prob[i] = calloc((size_t)tmodel->num_states, sizeof(double));
    }

    tmodel->emit_dp = calloc((size_t)tmodel->num_states, sizeof(double*));
    for(uint i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_dp[i] = calloc((size_t)tmodel->num_obs, sizeof(double));
    }

    tmodel->emit_mu = calloc((size_t)tmodel->num_states, sizeof(double*));
    for(uint i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_mu[i] = calloc((size_t)tmodel->num_obs, sizeof(double));
    }

    tmodel->emit_sigma = calloc((size_t)tmodel->num_states, sizeof(double*));
    for(uint i = 0; i < tmodel->num_states; i++) {
        tmodel->emit_sigma[i] = calloc((size_t)tmodel->num_obs, sizeof(double));
    }
}

static void _tmodel_free(tmodel_t* tmodel) {
    tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);

    if(tmodel->start_prob) {
        free(tmodel->start_prob);
    }

    if(tmodel->trans_prob) {
        for(uint i = 0; i < tmodel->num_states; i++) {
            if(tmodel->trans_prob[i]) {
                free(tmodel->trans_prob[i]);
            }
        }
        free(tmodel->trans_prob);
    }

    if(tmodel->emit_dp) {
        for(uint i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_dp[i]) {
                free(tmodel->emit_dp[i]);
            }
        }
        free(tmodel->emit_dp);
    }

    if(tmodel->emit_mu) {
        for(uint i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_mu[i]) {
                free(tmodel->emit_mu[i]);
            }
        }
        free(tmodel->emit_mu);
    }

    if(tmodel->emit_sigma) {
        for(uint i = 0; i < tmodel->num_states; i++) {
            if(tmodel->emit_sigma[i]) {
                free(tmodel->emit_sigma[i]);
            }
        }
        free(tmodel->emit_sigma);
    }

    if(tmodel->state_space) {
        for(uint i = 0; i < tmodel->num_states; i++) {
            if(tmodel->state_space[i]) {
                free(tmodel->state_space[i]);
            }
        }
        free(tmodel->state_space);
    }

    if(tmodel->obs_space) {
        for(uint i = 0; i < tmodel->num_obs; i++) {
            if(tmodel->obs_space[i]) {
                free(tmodel->obs_space[i]);
            }
        }
        free(tmodel->obs_space);
    }

    tmodel->magic = 0;
    tor_free_(tmodel);
}

static tmodel_t* _tmodel_new(const char* model_json) {
    tmodel_t* tmodel = tor_malloc_zero_(sizeof(struct tmodel_s));
    tmodel->magic = TRAFFIC_MODEL_MAGIC;

    int ret = _parse_json_objects(model_json, 1, tmodel);
    if(ret == 0) {
        log_info(LD_GENERAL, "success parsing state and obs spaces");

        /* now we know the state and obs counts, allocate arrays */
        _tmodel_allocate_arrays(tmodel);

        /* now parse again, filling the arrays with probs */
        ret = _parse_json_objects(model_json, 0, tmodel);
        if(ret == 0) {
            log_info(LD_GENERAL, "success parsing trans, emit, and start probs");
        } else {
            log_warn(LD_GENERAL, "problem parsing trans, emit, and start probs");
        }
    } else {
        log_warn(LD_GENERAL, "problem parsing state and obs spaces");
    }

    if(ret == 0) {
        _tmodel_log_model(tmodel);
        return tmodel;
    } else {
        _tmodel_free(tmodel);
        return NULL;
    }
}

/* returns 0 if the traffic model body is parsed correctly and
 * the traffic model is loaded and ready to run viterbi on
 * closed streams. returns 1 if there is an error. */
int tmodel_set_traffic_model(uint32_t len, char *body) {
  /* body is NULL terminated, valid command syntax is:
   *  'TRUE {}\r\n' : command is to set a new model, the {} part
   *                  represents the actual JSON representation
   *                  of the model. The model JSON may be of
   *                  arbitrary length.
   *  'FALSE\r\n' : command is to unset, or remove any existing
   *                model that we have stored.
   */
  char* model_json = NULL;

  /* check if we have a model */
  if(len >= 5 && strncasecmp(body, "TRUE ", 5) == 0) {
      /* this is a command to parse and store a new model */
      model_json = &body[5];
  }

  /* we always free the previous model- if the length is too
   * short or we have a 'FALSE' command, or we are creating
   * a new model object. */
  if(global_traffic_model != NULL) {
      _tmodel_free(global_traffic_model);
      global_traffic_model = NULL;
      log_notice(LD_GENERAL, "Successfully freed a previously loaded traffic model");
  }

  /* now create a new one only if we had valid command input */
  if(model_json != NULL) {
      global_traffic_model = _tmodel_new(model_json);
      if(global_traffic_model) {
          log_notice(LD_GENERAL, "Successfully loaded a new traffic model from PrivCount");
      } else {
          log_warn(LD_GENERAL, "Unable to load traffic model from PrivCount");
          return 1;
      }
  }

  return 0;
}

static int64_t _tmodel_encode_delay(int64_t delay, tmodel_action_t obs) {
  int64_t encoded_delay = 0;

  if(obs == TMODEL_OBS_SENT_TO_ORIGIN) {
    /* '-' gets encoded as a negative delay */
    encoded_delay = (delay == 0) ? INTPTR_MIN : -delay;
  } else { /* TMODEL_OBS_RECV_FROM_ORIGIN */
    /* '+' gets encoded as a positive delay */
    encoded_delay = (delay == 0) ? INTPTR_MAX : delay;
  }

  return encoded_delay;
}

static int64_t _tmodel_decode_delay(int64_t encoded_delay, tmodel_action_t* obs_out) {
  tmodel_action_t obs = TMODEL_OBS_NONE;
  int64_t delay = 0;

  if(encoded_delay == INTPTR_MIN) {
    delay = 0;
    obs = TMODEL_OBS_SENT_TO_ORIGIN;
  } else if(encoded_delay == INTPTR_MAX) {
    delay = 0;
    obs = TMODEL_OBS_RECV_FROM_ORIGIN;
  } else if(encoded_delay < 0) {
    delay = -encoded_delay;
    obs = TMODEL_OBS_SENT_TO_ORIGIN;
  } else {
    delay = encoded_delay;
    obs = TMODEL_OBS_RECV_FROM_ORIGIN;
  }

  if(obs_out) {
    *obs_out = obs;
  }

  return delay;
}

static char* _tmodel_run_viterbi(tmodel_t* tmodel, tmodel_stream_t* tstream) {
  tor_assert(tmodel && tmodel->magic == TRAFFIC_MODEL_MAGIC);
  tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

  return NULL;
}

static void _tmodel_commit_packets(tmodel_stream_t* tstream) {
  tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

  /* do nothing if we have no packets */
  if(tstream->buf_length <= 0) {
    return;
  }

  /* first 'packet' gets all of the accumulated delay */
  int64_t delay = _tmodel_encode_delay(tstream->buf_delay, tstream->buf_obs);

  /* 'commit' the packet */
  smartlist_add(tstream->observations, (void*)delay);

  /* consume the packet length worth of data */
  if(tstream->buf_length >= TMODEL_PACKET_BYTE_COUNT) {
    tstream->buf_length -= TMODEL_PACKET_BYTE_COUNT;
  } else {
    tstream->buf_length = 0;
  }

  /* now process any remaining packets */
  while(tstream->buf_length > 0) {
    /* consecutive packets have no delay */
    delay = _tmodel_encode_delay((int64_t)0, tstream->buf_obs);

    /* 'commit' the packet */
    smartlist_add(tstream->observations, (void*)delay);

    /* consume the packet length worth of data */
    if(tstream->buf_length >= TMODEL_PACKET_BYTE_COUNT) {
      tstream->buf_length -= TMODEL_PACKET_BYTE_COUNT;
    } else {
      tstream->buf_length = 0;
    }
  }

  /* update this emission time as the previous emit time
   * so we can compute delays for future packets. */
  tstream->prev_emit_time = tstream->buf_emit_time;

  /* all of the buffered data has been committed */
  tstream->buf_length = 0;
  memset(&tstream->buf_emit_time, 0, sizeof(monotime_t));
  tstream->buf_delay = 0;
  tstream->buf_obs = TMODEL_OBS_NONE;
}

/* notify the traffic model that a stream transmitted a cell. */
void tmodel_stream_cell_transferred(tmodel_stream_t* tstream, size_t length,
    tmodel_action_t obs) {
  tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return;
  }

  monotime_t now;
  monotime_get(&now);

  /* check if we need to 'commit' any previous data */
  if (tstream->buf_length > 0) {
    int64_t elapsed = monotime_diff_usec(&tstream->buf_emit_time, &now);
    if (elapsed >= TMODEL_PACKET_TIME_TOLERENCE || tstream->buf_obs != obs) {
      _tmodel_commit_packets(tstream);
    }
  }

  /* start tracking new data */
  if (length > 0) {
    if (tstream->buf_length == 0) {
      tstream->buf_obs = obs;
      tstream->buf_emit_time = now;
      tstream->buf_delay = monotime_diff_usec(&tstream->prev_emit_time,
          &tstream->buf_emit_time);
    }
    tstream->buf_length += length;
  }
}

/* allocate storage for a new tmodel stream object that will be used
 * to track cell transmit times while a stream is active. */
tmodel_stream_t* tmodel_stream_new(void) {
  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return NULL;
  }

  tmodel_stream_t* tstream = tor_malloc_zero_(sizeof(struct tmodel_stream_s));
  tstream->magic = TRAFFIC_STREAM_MAGIC;

  monotime_get(&tstream->creation_time);
  tstream->prev_emit_time = tstream->creation_time;

  /* store packet delay times in the element pointers */
  tstream->observations = smartlist_new();

  return tstream;
}

/* notify the traffic model that the stream closed and should
 * be processed and freed. */
void tmodel_stream_free(tmodel_stream_t* tstream) {
  tor_assert(tstream && tstream->magic == TRAFFIC_STREAM_MAGIC);

  /* the stream is finished, we have all of the data we are going to get.
   * run viterbi to get the likliest paths for this stream, and then
   * send the json result string to PrivCount over the control port. */
  if (tmodel_is_active()) {
    char* viterbi_result = _tmodel_run_viterbi(global_traffic_model, tstream);
    control_event_privcount_viterbi(viterbi_result);
  }

  /* we had no need to allocate any memory other than the
   * element pointers used internally by the list. */
  smartlist_free(tstream->observations);

  tstream->magic = 0;
  tor_free_(tstream);
}

//def handle_stream(self, circuit_id, stream_id, stream_end_ts, secure_counters):
//    # use our observations to find the most likely path through the HMM,
//    # and then count some aggregate statistics about that path
//
//    if circuit_id in self.packets:
//        if stream_id in self.packets[circuit_id]:
//            # get the list of packet bundles
//            bundles = self.packets[circuit_id].pop(stream_id)
//            if bundles is not None and len(bundles) > 0:
//                # add the ending state
//                prev_packet_bundle = bundles[-1]
//
//                secs_since_prev_cell = stream_end_ts - prev_packet_bundle[2]
//                micros_since_prev_cell = max(long(0), long(secs_since_prev_cell * 1000000))
//
//                end_bundle = [None, micros_since_prev_cell, stream_end_ts, 1, 0]
//                bundles.append(end_bundle)
//
//                # we log a warning here in case PrivCount hangs in vitterbi
//                # (it could hang processing packets, but that's very unlikely)
//                stream_packet_count = sum(bundle[3] for bundle in bundles)
//                if stream_packet_count > TrafficModel.MAX_STREAM_PACKET_COUNT:
//                    # round the packet count to the nearest
//                    # TrafficModel.MAX_STREAM_PACKET_COUNT, for at least a little user
//                    # protection
//                    rounded_stream_packet_count = TrafficModel._integer_round(
//                                                  stream_packet_count,
//                                                  TrafficModel.MAX_STREAM_PACKET_COUNT)
//                    logging.info("Large stream packet count: ~{} packets in {} bundles. Stream packet limit is {} packets."
//                                 .format(rounded_stream_packet_count,
//                                         len(bundles),
//                                         TrafficModel.MAX_STREAM_PACKET_COUNT))
//
//                # run viterbi to get the likliest path through our model given the observed delays
//                viterbi_start_time = clock()
//                likliest_states = self._run_viterbi(bundles)
//
//                # increment result counters
//                counter_start_time = clock()
//                if likliest_states is not None and len(likliest_states) > 0:
//                    self._increment_traffic_counters(bundles, likliest_states, secure_counters)
//
//                algo_end_time = clock()
//                algo_elapsed = algo_end_time - viterbi_start_time
//                viterbi_elapsed = counter_start_time - viterbi_start_time
//                counter_elapsed = algo_end_time - counter_start_time
//
//                if algo_elapsed > TrafficModel.MAX_STREAM_PROCESSING_TIME:
//                    rounded_num_packets = TrafficModel._integer_round(
//                                                  stream_packet_count,
//                                                  TrafficModel.MAX_STREAM_PACKET_COUNT)
//                    logging.warning("Long stream processing time: {:.1f} seconds to process ~{} packets exceeds limit of {:.1f} seconds. Breakdown: viterbi {:.1f} counter {:.1f}."
//                                    .format(algo_elapsed, rounded_num_packets,
//                                            TrafficModel.MAX_STREAM_PROCESSING_TIME,
//                                            viterbi_elapsed, counter_elapsed))
//                # TODO: secure delete?
//                #del likliest_states
//            # TODO: secure delete?
//            #del bundles
//
//        if len(self.packets[circuit_id]) == 0:
//            self.packets.pop(circuit_id, None)
//
//    # take this opportunity to clear any streams that stuck around too long
//    self._clear_expired_bundles()
