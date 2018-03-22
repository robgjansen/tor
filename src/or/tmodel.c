/*
 * tmodel.c
 *
 *  Created on: Feb 3, 2018
 *      Author: rjansen
 */

#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <math.h>

#include "tmodel.h"
#include "or.h"
#include "config.h"
#include "compat.h"
#include "compat_time.h"
#include "container.h"
#include "control.h"
#include "torlog.h"
#include "util.h"
#include "util_bug.h"
#include "workqueue.h"

/* magic for memory checking */
#define TRAFFIC_MAGIC 0xAABBCCDD
#define TRAFFIC_MAGIC_HMM 0xBBDDAACC
#define TRAFFIC_MAGIC_PACKETS 0xCCAABBDD
#define TRAFFIC_MAGIC_STREAMS 0xCCBBAADD

/* max lengths used for string parsing */
#define TMODEL_MAX_STATE_STR_LEN 63
#define TMODEL_MAX_OBS_STR_LEN 7

/* the approximate number of payload bytes for a packet */
#define TMODEL_PACKET_BYTE_COUNT 1434
/* assume a packet arrived at the same time if it arrived
 * within this many microseconds */
#define TMODEL_PACKET_TIME_TOLERENCE 2

/* SQRT_2_PI = math.sqrt(2*math.pi) */
#define TMODEL_SQRT_2_PI 2.5066282746310002

/* maximum length that PrivCount will accept without closing connection
 * we subtract some bytes to allow some room for the controller to add its
 * event code, timestamp, and field name. */
#define TMODEL_MAX_JSON_RESULT_LEN ((1024*1024*200)-128)

/* traffic model observation code symbols */
#define TMODEL_OBS_CODE_PACKET_TO_SERVER "+"
#define TMODEL_OBS_CODE_PACKET_TO_ORIGIN "-"
#define TMODEL_OBS_CODE_STREAM "$"
#define TMODEL_OBS_CODE_END "F"
#define TMODEL_OBS_CODE_UNKNOWN "?"

/* the total size of this struct should fit inside a void* pointer
 * because we are storing this inside smartlist pointers. */
typedef struct tmodel_delay_s {
  tmodel_obs_type_t otype : 3;
  long unsigned int delay : ((sizeof(void*)*8)-3);
} tmodel_delay_t;

/* The tmodel_packets internal elements (see tmodel.h for typedef).
 * Holds information about packets sent on the stream. */
struct tmodel_packets_s {
  /* Time the stream was created */
  monotime_t creation_time;

  /* uncommitted packet info. we hold info until a tolerence
   * so that we can count data that arrives at the same time
   * as part of the same packets. */
  monotime_t buf_time;
  size_t buf_length;
  tmodel_obs_type_t buf_obstype;

  /* committed observations */
  smartlist_t* packets;

  /* for memory checking */
  uint magic;
};

/* The tmodel_streams internal elements (see tmodel.h for typedef).
 * Holds information about streams used on the circuit. */
struct tmodel_streams_s {
  /* Time the circuit was created */
  monotime_t creation_time;

  monotime_t buf_time;
  tmodel_obs_type_t buf_obstype;

  /* committed observations */
  smartlist_t* streams;

  /* for memory checking */
  uint magic;
};

/* An opaque structure representing a hidden markov stream or packet
 * model. The internals of this structure are not intended to be
 * accessed outside of the tmodel.c file. */
typedef struct tmodel_hmm_s tmodel_hmm_t;

/* the hidden markov model internal elements.
 * WARNING if any elements change, we must update tmodel_deepcopy
 * to make sure the new memory gets duplicated correctly for the
 * viterbi workers. */
struct tmodel_hmm_s {
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
  /* the max string length of all states in the state space */
  size_t max_state_str_length;

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
  /* lognormal distributions use mu and sigma */
  double** emit_mu;
  double** emit_sigma;
  /* exponential distributions use lambda */
  double** emit_lambda;

  /* for memory checking */
  uint magic;
};

/* An opaque structure representing a traffic model. The internals
 * of this structure are not intended to be accessed outside of the
 * tmodel.c file. */
typedef struct tmodel_s tmodel_t;

/* the tmodel internal elements.
 * WARNING if any elements change, we must update tmodel_deepcopy
 * to make sure the new memory gets duplicated correctly for the
 * viterbi workers. */
struct tmodel_s {
  /* the model used for packets on a stream */
  tmodel_hmm_t* hmm_packets;

  /* the model used for streams on a circuit */
  tmodel_hmm_t* hmm_streams;

  /* for memory checking */
  uint magic;
};

/* global pointer to traffic model state */
static tmodel_t* global_traffic_model = NULL;
tor_mutex_t* global_traffic_model_lock;

uint64_t num_outstanding_models = 0;
uint64_t num_outstanding_packets = 0;
uint64_t num_outstanding_streams = 0;
uint64_t num_outstanding_jobs = 0;

/* forward declarations so the traffic model code can utilize
 * the viterbi worker thread pool.  */
static int _viterbi_workers_init(uint num_workers);
static void _viterbi_workers_sync(void);
static int _viterbi_thread_pool_is_ready(void);
static void _viterbi_worker_assign(tmodel_packets_t* tpackets,
    tmodel_streams_t* tstreams);

/* returns true if we want to know about cells on exit streams,
 * false otherwise. */
int tmodel_is_active(void) {
  if (get_options()->EnablePrivCount && global_traffic_model != NULL
      && global_traffic_model->magic == TRAFFIC_MAGIC) {
    return 1;
  }
  return 0;
}

/* return the string observation code encoding the type
 * of distribution used to model the observation. */
static const char* _tmodel_obstype_to_code(tmodel_obs_type_t obstype) {
  switch(obstype) {
    case TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN:
      /* '+' means a packet was sent away from the client side.
       * uses a lognorm distribution. */
      return TMODEL_OBS_CODE_PACKET_TO_SERVER;
    case TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN:
      /* '-' means a packet was sent toward the client side.
       * uses a lognorm distribution. */
      return TMODEL_OBS_CODE_PACKET_TO_ORIGIN;
    case TMODEL_OBSTYPE_STREAM_NEW:
      /* '$' means a stream was observed */
      return TMODEL_OBS_CODE_STREAM;
    case TMODEL_OBSTYPE_PACKETS_FINISHED:
    case TMODEL_OBSTYPE_STREAMS_FINISHED:
      /* 'F' means the stream or circuit ended */
      return TMODEL_OBS_CODE_END;
    default:
    case TMODEL_OBSTYPE_NONE:
      return TMODEL_OBS_CODE_UNKNOWN;
  }
}

static uint _tmodel_hmm_obsstr_to_index(tmodel_hmm_t* hmm, const char* obs_name) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  for (uint i = 0; i < hmm->num_obs; i++) {
    log_debug(LD_GENERAL, "Searching for '%s', obs space element '%s'",
        obs_name, hmm->obs_space[i]);
    if (strncasecmp(hmm->obs_space[i], obs_name, TMODEL_MAX_OBS_STR_LEN) == 0) {
      return i;
    }
  }

  log_warn(LD_GENERAL, "Unable to find index for observation string '%s'",
      obs_name);
  return UINT_MAX;
}

static uint _tmodel_hmm_obstype_to_index(tmodel_hmm_t* hmm, tmodel_obs_type_t otype) {
  const char* obs_str = _tmodel_obstype_to_code(otype);
  return _tmodel_hmm_obsstr_to_index(hmm, obs_str);
}

static uint _tmodel_hmm_get_state_index(tmodel_hmm_t* hmm, char* state_name) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  for (uint i = 0; i < hmm->num_states; i++) {
    if (strncasecmp(hmm->state_space[i], state_name, 63) == 0) {
      return i;
    }
  }

  log_warn(LD_GENERAL, "unable to find state index for state name '%s'", state_name);
  return UINT_MAX;
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
  for (i = 1; json[i] != '\0' && depth > 0; i++) {
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

static uint _parse_json_state_space(const char* json, int obj_end_pos,
    tmodel_hmm_t* hmm) {
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
    if (hmm) {
      hmm->state_space[count] = strndup(state_name, 63);
      size_t state_str_len = strnlen(hmm->state_space[count], 64);
      if(state_str_len > hmm->max_state_str_length) {
        hmm->max_state_str_length = state_str_len;
      }
    }
    count++;

    /* fast forward to the end of the name,
     * plus 2 for the quote characters. */
    i += strnlen(state_name, 63) + 2;

    /* check if we have another element, which is normally
     * separated by a comma, but we separate by a ';'. */
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return count;
}
static uint _parse_json_obs_space(const char* json, int obj_end_pos,
    tmodel_hmm_t* hmm) {
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
    if (hmm) {
      hmm->obs_space[count] = strndup(obs_name, 7);
    }
    count++;

    /* fast forward to the end of the name,
     * plus 2 for the quote characters. */
    i += strnlen(obs_name, 7) + 2;

    /* check if we have another element, which is normally
     * separated by a comma, but we separate by a ';'. */
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return count;
}

static int _parse_json_emit_prob(const char* json, int obj_end_pos,
    tmodel_hmm_t* hmm) {
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

    int state_index = _tmodel_hmm_get_state_index(hmm, state_name);
    if (state_index < 0) {
      log_warn(LD_GENERAL, "unable to find state index");
      return 1;
    }

    /* iterate the inner dict object */
    while (json[i] != '}' && i <= inner_obj_end_pos) {
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

      if (json[i] != '[') {
        log_warn(LD_GENERAL, "unable to find emit list start bracket");
        return 1;
      }

      int emit_vals_list_len = _json_find_object_end_pos(&json[i]);
      if (emit_vals_list_len < 0) {
        log_warn(LD_GENERAL, "unable to find emit list len");
        return 1;
      }

      int obs_index = _tmodel_hmm_obsstr_to_index(hmm, obs);
      if (obs_index < 0) {
        log_warn(LD_GENERAL, "unable to find emit obs index");
        return 1;
      }

      if (strncasecmp(obs, TMODEL_OBS_CODE_PACKET_TO_SERVER, 1) == 0 ||
          strncasecmp(obs, TMODEL_OBS_CODE_PACKET_TO_ORIGIN, 1) == 0 ||
          strncasecmp(obs, TMODEL_OBS_CODE_STREAM, 1) == 0) {
        /* lognormal or exponential distribution params */
        double dp = 0.0, mu = 0.0, sigma = 0.0, lambda = 0.0;
        n_assigned = sscanf(&json[i], "[%lf;%lf;%lf;%lf]", &dp, &mu, &sigma, &lambda);
        if (n_assigned != 4) {
          log_warn(LD_GENERAL, "sscanf problem parsing emit values");
          return 1;
        }

        /* process the items */
        log_debug(LD_GENERAL,
            "found emit for state '%s' and obs '%s': "
            "dp='%f' mu='%f' sigma='%f' lambda='%f'",
            state_name, obs, dp, mu, sigma, lambda);

        hmm->emit_dp[state_index][obs_index] = dp;
        hmm->emit_mu[state_index][obs_index] = mu;
        hmm->emit_sigma[state_index][obs_index] = sigma;
        hmm->emit_lambda[state_index][obs_index] = lambda;
      } else if(strncasecmp(obs, TMODEL_OBS_CODE_END, 1) == 0) {
        /* state 'F' */
        double dp = 0.0;
        n_assigned = sscanf(&json[i], "[%lf]", &dp);
        if (n_assigned != 1) {
          log_warn(LD_GENERAL, "sscanf problem parsing emit values");
          return 1;
        }

        /* process the items */
        log_debug(LD_GENERAL,
            "found emit for state '%s' and obs '%s': dp='%f'",
            state_name, obs, dp);

        hmm->emit_dp[state_index][obs_index] = dp;
      } else {
        log_warn(LD_GENERAL, "found unsupported observation code '%s", obs);
        return 1;
      }

      /* fast forward to one past the end of the list */
      i += emit_vals_list_len;

      /* check if we have another element, which is normally
       * separated by a comma, but we separate by a ';'. */
      if (json[i] == ';') {
        i++;
      }
    }

    if (json[i] != '}') {
      log_warn(LD_GENERAL, "unable to find emit closing brace");
      return 1;
    }

    /* jump ahead one, past the end of the inner dict */
    i++;

    /* fast forward to the next entry or the end */
    while (json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
      i++;
    }

    /* check if we have another element, which is normally
     * separated by a comma, but we separate by a ';'. */
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return 0;
}

static int _parse_json_trans_prob(const char* json, int obj_end_pos,
    tmodel_hmm_t* hmm) {
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

    int src_index = _tmodel_hmm_get_state_index(hmm, state_name_src);
    if (src_index < 0) {
      log_warn(LD_GENERAL, "unable to find trans src state index");
      return 1;
    }

    /* iterate the inner dict object */
    while (json[i] != '}' && i <= inner_obj_end_pos) {
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

      int dst_index = _tmodel_hmm_get_state_index(hmm, state_name_dst);
      if (dst_index < 0) {
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

      hmm->trans_prob[src_index][dst_index] = trans_prob;

      /* fast forward to the next entry or the end */
      while (json[i] != ';' && json[i] != '}' && i < inner_obj_end_pos) {
        i++;
      }

      /* check if we have another element, which is normally
       * separated by a comma, but we separate by a ';'. */
      if (json[i] == ';') {
        i++;
      }
    }

    /* jump ahead one, past the end of the inner dict */
    i++;

    /* fast forward to the next entry or the end */
    while (json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
      i++;
    }

    /* check if we have another element, which is normally
     * separated by a comma, but we separate by a ';'. */
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return 0;
}

static int _parse_json_start_prob(const char* json, int obj_end_pos,
    tmodel_hmm_t* hmm) {
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

    int state_index = _tmodel_hmm_get_state_index(hmm, state_name);
    if (state_index < 0) {
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
    log_debug(LD_GENERAL, "found state '%s' and start_prob '%f'", state_name,
        start_prob);

    hmm->start_prob[state_index] = start_prob;

    /* fast forward to the next entry or the end */
    while (json[i] != ';' && json[i] != '}' && i < obj_end_pos) {
      i++;
    }

    /* check if we have another element, which is normally
     * separated by a comma, but we separate by a ';'. */
    if (json[i] == ';') {
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
static int _parse_json_hmm_objects(const char* json,
    int obj_end_pos, int parse_spaces, tmodel_hmm_t* hmm) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  int i = 0, j = 0;
  if (json[i] != '{') {
    return 1;
  } else {
    i++;
  }

  while (json[i] != '}' && i <= obj_end_pos) {
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
    if (json[i] == '[' && strncasecmp(input_type, "state_space", 6) == 0) {
      if (parse_spaces) {
        /* first count the number of states */
        uint num_states = _parse_json_state_space(&json[i], j, NULL);
        if (num_states <= 0) {
          log_warn(LD_GENERAL,
              "_parse_json_state_space failed to count states (1)");
          return 1;
        }

        /* allocate the state array */
        hmm->num_states = num_states;
        hmm->state_space = calloc(hmm->num_states, sizeof(char*));

        /* now actually store the values by giving a model */
        num_states = _parse_json_state_space(&json[i], j, hmm);
        if (num_states <= 0) {
          log_warn(LD_GENERAL,
              "_parse_json_state_space failed to count states (2)");
          return 1;
        }
      }
    } else if (json[i] == '['
        && strncasecmp(input_type, "observation_space", 17) == 0) {
      if (parse_spaces) {
        /* first count the number of states */
        uint num_obs = _parse_json_obs_space(&json[i], j, NULL);
        if (num_obs <= 0) {
          log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (1)");
          return 1;
        }

        /* allocate the obs array */
        hmm->num_obs = num_obs;
        hmm->obs_space = calloc(hmm->num_obs, sizeof(char*));

        /* now actually store the values by giving a model */
        num_obs = _parse_json_obs_space(&json[i], j, hmm);
        if (num_obs <= 0) {
          log_warn(LD_GENERAL, "_parse_json_obs_space failed to count obs (2)");
          return 1;
        }
      }
    } else if (json[i] == '{'
        && strncasecmp(input_type, "emission_probability", 20) == 0) {
      if (!parse_spaces && _parse_json_emit_prob(&json[i], j, hmm) != 0) {
        log_warn(LD_GENERAL, "_parse_json_emit_prob failed");
        return 1;
      }
    } else if (json[i] == '{'
        && strncasecmp(input_type, "transition_probability", 22) == 0) {
      if (!parse_spaces && _parse_json_trans_prob(&json[i], j, hmm) != 0) {
        log_warn(LD_GENERAL, "_parse_json_trans_prob failed");
        return 1;
      }
    } else if (json[i] == '{'
        && strncasecmp(input_type, "start_probability", 17) == 0) {
      if (!parse_spaces && _parse_json_start_prob(&json[i], j, hmm) != 0) {
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
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return 0;
}

static void _tmodel_hmm_allocate_arrays(tmodel_hmm_t* hmm) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  hmm->start_prob = calloc((size_t) hmm->num_states, sizeof(double));

  hmm->trans_prob = calloc((size_t) hmm->num_states, sizeof(double*));
  for (uint i = 0; i < hmm->num_states; i++) {
    hmm->trans_prob[i] = calloc((size_t) hmm->num_states, sizeof(double));
  }

  hmm->emit_dp = calloc((size_t) hmm->num_states, sizeof(double*));
  for (uint i = 0; i < hmm->num_states; i++) {
    hmm->emit_dp[i] = calloc((size_t) hmm->num_obs, sizeof(double));
  }

  hmm->emit_mu = calloc((size_t) hmm->num_states, sizeof(double*));
  for (uint i = 0; i < hmm->num_states; i++) {
    hmm->emit_mu[i] = calloc((size_t) hmm->num_obs, sizeof(double));
  }

  hmm->emit_sigma = calloc((size_t) hmm->num_states, sizeof(double*));
  for (uint i = 0; i < hmm->num_states; i++) {
    hmm->emit_sigma[i] = calloc((size_t) hmm->num_obs, sizeof(double));
  }

  hmm->emit_lambda = calloc((size_t) hmm->num_states, sizeof(double*));
  for (uint i = 0; i < hmm->num_states; i++) {
    hmm->emit_lambda[i] = calloc((size_t) hmm->num_obs, sizeof(double));
  }
}

static int _parse_json_hmm(const char* json,
    int i, int j, tmodel_hmm_t** hmm, const char* name) {
  (*hmm) = tor_malloc_zero_(sizeof(struct tmodel_hmm_s));
  (*hmm)->magic = TRAFFIC_MAGIC_HMM;

  int ret = _parse_json_hmm_objects(&json[i], j, 1, *hmm);
  if (ret == 0) {
    log_info(LD_GENERAL, "success parsing %s state and obs spaces", name);

    /* now we know the state and obs counts, allocate arrays */
    _tmodel_hmm_allocate_arrays(*hmm);

    /* now parse again, filling the arrays with probs */
    ret = _parse_json_hmm_objects(&json[i], j, 0, *hmm);
    if (ret == 0) {
      log_info(LD_GENERAL, "success parsing %s trans, emit, and start probs", name);
    } else {
      log_warn(LD_GENERAL, "problem parsing %s trans, emit, and start probs", name);
      (*hmm)->magic = 0;
      tor_free_(*hmm);
      (*hmm) = NULL;
    }
  } else {
    log_warn(LD_GENERAL, "problem parsing %s state and obs spaces", name);
    (*hmm)->magic = 0;
    tor_free_(*hmm);
    (*hmm) = NULL;
  }

  return ret;
}

/* we loop twice, once to parse the state space and observation
 * space which is only done if parse_spaces=1. on the second
 * pass, we parse the trans_prob, emit_prob, an start_prob
 * objects, given the space and observation spaces that we
 * parsed in the first step. */
static int _parse_json_objects(const char* json, tmodel_t* tmodel) {
  tor_assert(tmodel && tmodel->magic == TRAFFIC_MAGIC);

  int i = 0, j = 0;
  if (json[i] != '{') {
    return 1;
  } else {
    i++;
  }

  while (json[i] != '}') {
    /* static buffer to hold the parsed type */
    char model_type[32];
    memset(model_type, 0, 32);

    /* read the type. will be one of the following:
     *   '"packet_model"', or '"stream_model"',
     * they may appear in any order.
     */
    int n_assigned = sscanf(&json[i], "\"%30[^\"]", model_type);
    if (n_assigned != 1) {
      return 1;
    }

    /* fast forward to the object starting position,
     * which will be at 1 past the ':' character.
     * add 3 for the "": chars */
    i += strnlen(model_type, 30) + 3;

    /* find the end of the object */
    j = _json_find_object_end_pos(&json[i]);
    if (j < 0) {
      return 1;
    }

    log_info(LD_GENERAL, "found object '%s' of length %d", model_type, j);

    /* handle each object type */
    if (json[i] == '{' &&
        strncasecmp(model_type, "packet_model", 12) == 0) {
      int ret = _parse_json_hmm(json, i, j, &tmodel->hmm_packets, "packet model");
      if(ret != 0) {
        return 1;
      }
    } else if (json[i] == '{' &&
        strncasecmp(model_type, "stream_model", 12) == 0) {
      int ret = _parse_json_hmm(json, i, j, &tmodel->hmm_streams, "stream model");
      if(ret != 0) {
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
    if (json[i] == ';') {
      i++;
    }
  }

  /* success! */
  return 0;
}

static void _tmodel_log_hmm(tmodel_hmm_t* hmm, const char* hmm_name) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  if (hmm->state_space) {
    log_info(LD_GENERAL, "Logging %s state space", hmm_name);
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->state_space[i]) {
        log_info(LD_GENERAL, "found state_space[%i] '%s'", i,
            hmm->state_space[i]);
      }
    }
  }

  if (hmm->obs_space) {
    log_info(LD_GENERAL, "Logging %s observation space", hmm_name);
    for (uint i = 0; i < hmm->num_obs; i++) {
      if (hmm->obs_space[i]) {
        log_info(LD_GENERAL, "found obs_space[%i] '%s'", i,
            hmm->obs_space[i]);
      }
    }
  }

  if (hmm->start_prob) {
    log_info(LD_GENERAL, "Logging %s start probabilities", hmm_name);
    for (uint i = 0; i < hmm->num_states; i++) {
      log_info(LD_GENERAL, "found start_prob[%i] '%f'", i,
          hmm->start_prob[i]);
    }
  }

  if (hmm->trans_prob) {
    log_info(LD_GENERAL, "Logging %s transition probabilities", hmm_name);
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->trans_prob[i]) {
        for (uint j = 0; j < hmm->num_states; j++) {
          log_info(LD_GENERAL, "found trans_prob[%i][%i] '%f'", i, j,
              hmm->trans_prob[i][j]);
        }
      }
    }
  }

  if (hmm->emit_dp && hmm->emit_mu && hmm->emit_sigma && hmm->emit_lambda) {
    log_info(LD_GENERAL, "Logging %s emission values", hmm_name);
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->emit_dp[i] && hmm->emit_mu[i] && hmm->emit_sigma[i] && hmm->emit_lambda[i]) {
        for (uint j = 0; j < hmm->num_obs; j++) {
          log_info(LD_GENERAL, "found emit_dp[%i][%i] '%f'", i, j,
              hmm->emit_dp[i][j]);
          log_info(LD_GENERAL, "found emit_mu[%i][%i] '%f'", i, j,
              hmm->emit_mu[i][j]);
          log_info(LD_GENERAL, "found emit_sigma[%i][%i] '%f'", i, j,
              hmm->emit_sigma[i][j]);
          log_info(LD_GENERAL, "found emit_lambda[%i][%i] '%f'", i, j,
              hmm->emit_lambda[i][j]);
        }
      }
    }
  }
}

static void _tmodel_log_model(tmodel_t* tmodel) {
  tor_assert(tmodel && tmodel->magic == TRAFFIC_MAGIC);
  if(tmodel->hmm_packets) {
    _tmodel_log_hmm(tmodel->hmm_packets, "packet model");
  }
  if(tmodel->hmm_streams) {
    _tmodel_log_hmm(tmodel->hmm_streams, "stream model");
  }
}

static void _tmodel_hmm_free(tmodel_hmm_t* hmm) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  if (hmm->start_prob) {
    free(hmm->start_prob);
  }

  if (hmm->trans_prob) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->trans_prob[i]) {
        free(hmm->trans_prob[i]);
      }
    }
    free(hmm->trans_prob);
  }

  if (hmm->emit_dp) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->emit_dp[i]) {
        free(hmm->emit_dp[i]);
      }
    }
    free(hmm->emit_dp);
  }

  if (hmm->emit_mu) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->emit_mu[i]) {
        free(hmm->emit_mu[i]);
      }
    }
    free(hmm->emit_mu);
  }

  if (hmm->emit_sigma) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->emit_sigma[i]) {
        free(hmm->emit_sigma[i]);
      }
    }
    free(hmm->emit_sigma);
  }

  if (hmm->emit_lambda) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->emit_lambda[i]) {
        free(hmm->emit_lambda[i]);
      }
    }
    free(hmm->emit_lambda);
  }

  if (hmm->state_space) {
    for (uint i = 0; i < hmm->num_states; i++) {
      if (hmm->state_space[i]) {
        free(hmm->state_space[i]);
      }
    }
    free(hmm->state_space);
  }

  if (hmm->obs_space) {
    for (uint i = 0; i < hmm->num_obs; i++) {
      if (hmm->obs_space[i]) {
        free(hmm->obs_space[i]);
      }
    }
    free(hmm->obs_space);
  }

  hmm->magic = 0;
  tor_free_(hmm);
}

static void _tmodel_free(tmodel_t* tmodel) {
  tor_assert(tmodel && tmodel->magic == TRAFFIC_MAGIC);

  if(tmodel->hmm_packets) {
    _tmodel_hmm_free(tmodel->hmm_packets);
  }
  if(tmodel->hmm_streams) {
    _tmodel_hmm_free(tmodel->hmm_streams);
  }

  tmodel->magic = 0;
  tor_free_(tmodel);

  if(num_outstanding_models > 0) {
    num_outstanding_models--;
  }
}

static tmodel_hmm_t* _tmodel_hmm_deepcopy(tmodel_hmm_t* hmm) {
  if(hmm == NULL || hmm->magic != TRAFFIC_MAGIC_HMM ||
      !hmm->state_space || !hmm->obs_space ||
      !hmm->trans_prob || !hmm->emit_dp ||
      !hmm->emit_mu || !hmm->emit_sigma || !hmm->emit_lambda) {
    return NULL;
  }

  tmodel_hmm_t* copy = tor_malloc_zero_(sizeof(struct tmodel_hmm_s));

  copy->magic = hmm->magic;
  copy->num_states = hmm->num_states;
  copy->num_obs = hmm->num_obs;
  copy->max_state_str_length = hmm->max_state_str_length;

  copy->state_space = calloc(copy->num_states, sizeof(char*));
  copy->obs_space = calloc(copy->num_obs, sizeof(char*));
  _tmodel_hmm_allocate_arrays(copy);

  for (uint i = 0; i < copy->num_states; i++) {
    copy->state_space[i] = strndup(hmm->state_space[i], hmm->max_state_str_length);
    copy->start_prob[i] = hmm->start_prob[i];
  }

  for (uint i = 0; i < copy->num_obs; i++) {
    copy->obs_space[i] = strndup(hmm->obs_space[i], 8);
  }

  for (uint i = 0; i < copy->num_states; i++) {
    for(uint j = 0; j < copy->num_states; j++) {
      copy->trans_prob[i][j] = hmm->trans_prob[i][j];
    }
  }

  for (uint i = 0; i < copy->num_states; i++) {
    for(uint j = 0; j < copy->num_obs; j++) {
      copy->emit_dp[i][j] = hmm->emit_dp[i][j];
    }
  }

  for (uint i = 0; i < copy->num_states; i++) {
    for(uint j = 0; j < copy->num_obs; j++) {
      copy->emit_mu[i][j] = hmm->emit_mu[i][j];
    }
  }

  for (uint i = 0; i < copy->num_states; i++) {
    for(uint j = 0; j < copy->num_obs; j++) {
      copy->emit_sigma[i][j] = hmm->emit_sigma[i][j];
    }
  }

  for (uint i = 0; i < copy->num_states; i++) {
    for(uint j = 0; j < copy->num_obs; j++) {
      copy->emit_lambda[i][j] = hmm->emit_lambda[i][j];
    }
  }

  return copy;
}

static tmodel_t* _tmodel_deepcopy(tmodel_t* tmodel) {
  if(tmodel == NULL || tmodel->magic != TRAFFIC_MAGIC) {
    return NULL;
  }

  tmodel_t* copy = tor_malloc_zero_(sizeof(struct tmodel_s));

  copy->magic = tmodel->magic;

  if(tmodel->hmm_packets) {
    copy->hmm_packets = _tmodel_hmm_deepcopy(tmodel->hmm_packets);
  }
  if(tmodel->hmm_streams) {
    copy->hmm_streams = _tmodel_hmm_deepcopy(tmodel->hmm_streams);
  }

  num_outstanding_models++;

  return copy;
}

static tmodel_t* _tmodel_new(const char* model_json) {
  tmodel_t* tmodel = tor_malloc_zero_(sizeof(struct tmodel_s));
  tmodel->magic = TRAFFIC_MAGIC;
  num_outstanding_models++;

  int ret = _parse_json_objects(model_json, tmodel);
  if (ret == 0) {
    log_info(LD_GENERAL, "success parsing hidden markov model(s)");
  } else {
    log_warn(LD_GENERAL, "problem parsing hidden markov model(s)");
  }

  if (ret == 0) {
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
int tmodel_set_traffic_model(uint32_t len, const char *body) {
  /* body is NULL terminated, valid command syntax is:
   *  'TRUE {}\r\n' : command is to set a new model, the {} part
   *                  represents the actual JSON representation
   *                  of the model. The model JSON may be of
   *                  arbitrary length.
   *  'FALSE\r\n' : command is to unset, or remove any existing
   *                model that we have stored.
   */
  int return_code = 0;

  /* create a new model only if we had valid command input */
  tmodel_t* traffic_model = NULL;
  if (len >= 5 && strncasecmp(body, "TRUE ", 5) == 0) {
    traffic_model = _tmodel_new(&body[5]);
    if (traffic_model) {
      log_notice(LD_GENERAL,
          "Successfully loaded a new traffic model from PrivCount");
    } else {
      log_warn(LD_GENERAL, "Unable to load traffic model from PrivCount");
      return_code = 1;
    }
  }

  /* before we edit the global model, init the lock if needed */
  if(!global_traffic_model_lock) {
    global_traffic_model_lock = tor_malloc_zero_(sizeof(tor_mutex_t));
    tor_mutex_init(global_traffic_model_lock);
  }

  /* we always free the previous model if the length is too
   * short or we have a 'FALSE' command, or we are creating
   * a new model object. */
  tor_mutex_acquire(global_traffic_model_lock);

  if (global_traffic_model != NULL) {
    _tmodel_free(global_traffic_model);
    global_traffic_model = NULL;

    log_notice(LD_GENERAL,
        "Successfully freed a previously loaded traffic model");
  }

  if (traffic_model != NULL) {
    global_traffic_model = traffic_model;
  }

  tor_mutex_release(global_traffic_model_lock);

  int num_workers = get_options()->PrivCountNumViterbiWorkers;
  int sync_was_done = 0;
  if (num_workers > 0) {
    /* Initiate num_workers threads if needed, and record
     * whether or not this call created a new thread pool
     * and thus synchronized the latest traffic model on
     * the workers.*/
    sync_was_done = _viterbi_workers_init((uint)num_workers);
  }

  if(!sync_was_done) {
    /* Make sure we attempt to synchronize the current
     * global_traffic_model on all of the threads that we originally
     * created (if any exist). If we stopped collecting traffic
     * model stats, this will cause the threads will free their
     * current traffic model instance and wait for another update.
     * If we start collecting a second round, even though num_workers
     * might be 0, we still sync the traffic model in case that the
     * workers are re-enabled in the middle of a collection.
     * (In any case, the workers won't run the jobs unless the
     * config option is positive.) */
    _viterbi_workers_sync();
  }

  log_notice(LD_GENERAL, "Outstanding traffic model objects: "
      "models="U64_FORMAT" streams="U64_FORMAT" "
      "packets="U64_FORMAT" jobs="U64_FORMAT,
      U64_PRINTF_ARG(num_outstanding_models),
      U64_PRINTF_ARG(num_outstanding_streams),
      U64_PRINTF_ARG(num_outstanding_packets),
      U64_PRINTF_ARG(num_outstanding_jobs));

  return return_code;
}

/*************************************
 ** Traffic model stream processing **
 *************************************/

static char* _encode_viterbi_path(tmodel_hmm_t* hmm, smartlist_t* observations,
    uint* viterbi_path, uint path_len) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  if(!observations || !viterbi_path ||
      path_len != (uint)smartlist_len(observations)) {
    log_warn(LD_BUG, "Problem verifying input params before "
        "encoding viterbi path as json");
    return NULL;
  }

  uint obs_index, state_index;

  /* our json object will be something like:
   *   [["m10s1";"+";35432];["m2s4";"+";0];["m4s2";"-";100];["m4sEnd";"F";0]]
   * each observation (i.e., packet) will require:
   *   9 chars for ["";"";];
   *   n chars for state, where n is at most tmodel->max_state_str_length
   *   1 char for either + or - or F
   *   20 chars, the most that an int64_t value will consume
   *       (INT64 range is -9223372036854775808 to 9223372036854775807)
   *   --------
   *   max total per packet is = 30 + n
   *
   * so for p packets, we need at most:
   *   p * (30 + n) characters
   *
   * if n is 7, that's 37 bytes per observation
   * we may go up to 100,000 or more packets on a really heavy stream
   *   which would be 3700000 bytes or about 3.7 MB in a pessimistic case
   *   this will get freed as soon as it is send to PrivCount
   * instead, we use the large buffer to build the string, and then
   *   truncate it before sending to the main thread (and then to PrivCount).
   */
  size_t n = hmm->max_state_str_length;
  size_t json_buffer_len = (size_t)(path_len * (30 + n));

  char* json_buffer = calloc(json_buffer_len, 1);
  size_t write_index = 0;
  size_t rem_space = json_buffer_len-1;

  int num_printed = 0;

  for(uint i = 0; i < path_len; i++) {
    void* element = smartlist_get(observations, i);
    tmodel_delay_t d;
    memmove(&d, &element, sizeof(void*));

    obs_index = _tmodel_hmm_obstype_to_index(hmm, d.otype);
    state_index = viterbi_path[i];

    /* sanity check */
    if(obs_index >= hmm->num_obs || state_index >= hmm->num_states) {
      /* these would overflow the respective arrays */
      log_warn(LD_BUG, "Can't print viterbi path json for packet %u/%u "
          "because obs_index (%u) or state_index (%u) is out of range",
          i, path_len-1, obs_index, state_index);
      free(json_buffer);
      return NULL;
    }

    num_printed = snprintf(&json_buffer[write_index], rem_space,
        "[\"%s\";\"%s\";%lu]%s",
        hmm->state_space[state_index],
        hmm->obs_space[obs_index],
        (long unsigned int)d.delay,
        (i == path_len-1) ? "" : ";");

    if(num_printed <= 0) {
      free(json_buffer);
      log_warn(LD_BUG, "Problem printing viterbi path json for "
          "packet %u/%u: snprintf returned %d", i, path_len-1, num_printed);
      return NULL;
    } else {
      rem_space -= (size_t)num_printed;
      write_index += (size_t)num_printed;
    }
  }

  /* get the final string and truncate the buffer */
  char* json = NULL;
  num_printed = tor_asprintf(&json, "[%s]", json_buffer);

  free(json_buffer);

  if(num_printed <= 0) {
    log_warn(LD_BUG, "Problem truncating viterbi path json buffer: "
        "tor_asprintf returned %d", num_printed);
    return NULL;
  } else {
    if(json && num_printed > TMODEL_MAX_JSON_RESULT_LEN) {
      log_warn(LD_GENERAL, "Encoded viterbi path json size is %ld, but the"
          "maximum supported size is %ld. Dropping result so we don't "
          "crash PrivCount.", (long)num_printed, (long)TMODEL_MAX_JSON_RESULT_LEN);
      free(json);
      return NULL;
    } else {
      log_info(LD_GENERAL,
          "Encoded viterbi path as json string of size %ld", (long)num_printed);
      return json;
    }
  }
}

static double _compute_delay_dx(long unsigned int delay) {
  if(delay <= 2) {
    return (double)1.0;
  }

  double ld = log((double)delay);
  long unsigned int li = (long unsigned int)ld;

  double ed = exp((double)li);
  long unsigned int ei = (long unsigned int)ed;

  return (double)ei;
}

static double _compute_delay_log(double dx, double mu, double sigma) {
  const double sqrt2pi = (const double)TMODEL_SQRT_2_PI;
  const double half = (const double)0.5;
  const double two = (const double)2.0;

  double log_prob = -log(dx*sigma*sqrt2pi) - half*pow(((log(dx)-mu)/sigma), two);
  return log_prob;
}

static char* _tmodel_run_viterbi(tmodel_hmm_t* hmm, smartlist_t* observations) {
  tor_assert(hmm && hmm->magic == TRAFFIC_MAGIC_HMM);

  /* our goal is to find the viterbi path and encode it as a json string */
  char* viterbi_json = NULL;

  const uint n_states = hmm->num_states;
  const uint n_obs = (uint)smartlist_len(observations);

  /* don't do any unnecessary work, and prevent array index underflow.
   * we must have at least one of ('+','-') or ('$') and also an ('F') event */
  if(n_obs <= 1) {
    log_info(LD_GENERAL, "Not running viterbi algorithm with no observations.");
    return viterbi_json;
  }

  /* initialize the auxiliary tables:
   *   table1 stores max probs
   *   table2 stores state index of max probs  */
  double** table1 = calloc(n_states, sizeof(double*));
  uint** table2 = calloc(n_states, sizeof(uint*));
  for(uint i = 0; i < n_states; i++) {
    table1[i] = calloc(n_obs, sizeof(double));
    table2[i] = calloc(n_obs, sizeof(uint));
  }

  /* list of most probable states for each observation.
   * we store indices into our state space string array. */
  uint* optimal_states = calloc(n_obs, sizeof(uint));
  memset(optimal_states, UINT_MAX, sizeof(uint) * n_obs);

  log_info(LD_GENERAL, "State setup done, running viterbi algorithm now");

  /* get some info about the first packet */
  void* element = smartlist_get(observations, 0);
  tmodel_delay_t d;
  memmove(&d, &element, sizeof(void*));

  double dx = _compute_delay_dx(d.delay);

  /* get the obs name index into the obs space */
  uint obs_index = _tmodel_hmm_obstype_to_index(hmm, d.otype);
  if(obs_index >= hmm->num_obs) {
    log_warn(LD_BUG, "Bug in viterbi: obs_index (%u) is out of range "
        "for observation 0/%u", obs_index, n_obs-1);
    goto cleanup; // will return NULL
  }

  for(uint i = 0; i < n_states; i++) {
    table1[i][0] = -INFINITY;
    table2[i][0] = UINT_MAX;

    if(hmm->start_prob[i] <= 0) {
      continue;
    }

    double dp = hmm->emit_dp[i][obs_index];
    double mu = hmm->emit_mu[i][obs_index];
    double sigma = hmm->emit_sigma[i][obs_index];
    double lambda = hmm->emit_lambda[i][obs_index];

    if(dp <= 0 || (sigma <= 0 && lambda <= 0)) {
      continue;
    }

    /* compute the probability of this observation occurring
     * in this state given the observed delay value. */
    double fit_logprob = 0.0;

    if(sigma > 0) {
      /* this state uses a lognormal distribution */
      fit_logprob = log(dp) + _compute_delay_log(dx, mu, sigma);
    } else {
      /* this state uses an exponential distribution */
      //double streams_per_microsecond = ((double)1.0) / ((double)d.delay);
      fit_logprob = log(dp) + log(lambda) - lambda*dx;
    }

    table1[i][0] = log(hmm->start_prob[i]) + fit_logprob;
  }

  /* loop through all packets/streams (except the first) */
  for(uint o = 1; o < n_obs; o++) {
    element = smartlist_get(observations, o);
    memmove(&d, &element, sizeof(void*));

    dx = _compute_delay_dx(d.delay);

    /* get the obs name index in the obs space */
    obs_index = _tmodel_hmm_obstype_to_index(hmm, d.otype);
    if(obs_index >= hmm->num_obs) {
      log_warn(LD_BUG, "Bug in viterbi: obs_index (%u) is out of range "
          "for observation %u/%u", obs_index, o, n_obs-1);
      goto cleanup; // will return NULL
    }

    /* loop through the state space */
    for(uint i = 0; i < n_states; i++) {
      table1[i][o] = -INFINITY;
      table2[i][o] = UINT_MAX;

      double max_trans_logprob = -INFINITY;
      uint max_trans_logprob_prev_state = UINT_MAX;

      /* Compute the maximum probability over all incoming edges
       * to state i, using the probability of the state at the
       * other end of the incoming edge (which we previously
       * and stored in table1). */
      for(uint j = 0; j < n_states; j++) {
        if(hmm->trans_prob[j][i] <= 0) {
          continue;
        }

        double trans_prob = table1[j][o-1] + log(hmm->trans_prob[j][i]);

        if(trans_prob > max_trans_logprob) {
          max_trans_logprob = trans_prob;
          max_trans_logprob_prev_state = j;
        }
      }

      table2[i][o] = max_trans_logprob_prev_state;

      double dp = hmm->emit_dp[i][obs_index];

      if(dp <= 0) {
        continue;
      }

      if(d.otype == TMODEL_OBSTYPE_PACKETS_FINISHED ||
          d.otype == TMODEL_OBSTYPE_STREAMS_FINISHED) {
        /* for 'F', we have no delay or distribution params */
        table1[i][o] = max_trans_logprob + log(dp);
        continue;
      }

      double mu = hmm->emit_mu[i][obs_index];
      double sigma = hmm->emit_sigma[i][obs_index];
      double lambda = hmm->emit_lambda[i][obs_index];

      if(sigma <= 0 && lambda <= 0) {
        continue;
      }

      /* compute the probability of this observation occurring
       * in this state given the observed delay value. */
      double fit_logprob = 0.0;

      if(sigma > 0) {
        /* this state uses a lognormal distribution */
        fit_logprob = log(dp) + _compute_delay_log(dx, mu, sigma);
      } else {
        /* this state uses an exponential distribution */
        //double streams_per_microsecond = ((double)1.0) / ((double)d.delay);
        fit_logprob = log(dp) + log(lambda) - lambda*dx;
      }

      /* store the max prob and prev state index for this packet/stream.
       * note that the case that this state has no positive trans_prob
       * is valid and it's OK if the max_prob is 0 for some states. */
      table1[i][o] = max_trans_logprob + fit_logprob;

      log_debug(LD_GENERAL,
          "Viterbi probability for state %u at observation %u/%u is %f",
          i, o, n_obs-1, table1[i][o]);
    }
  }

  /* get most probable final state */
  double optimal_prob = -INFINITY;
  for(uint i = 0; i < n_states; i++) {
    if(table1[i][n_obs-1] > optimal_prob) {
      optimal_prob = table1[i][n_obs-1];
      optimal_states[n_obs-1] = i;
    }
  }

  /* sanity check */
  if(optimal_states[n_obs-1] >= n_states) {
    log_warn(LD_BUG, "Bug in viterbi: optimal_states index (%u) is out of range "
        "for observation %u/%u, optimal probability was %f",
        optimal_states[n_obs-1], n_obs-1, n_obs-1, optimal_prob);
    goto cleanup; // will return NULL
  }

  /* now work backward for the remaining packets */
  for(uint p = n_obs-1; p > 0; p--) {
    uint opt_state = optimal_states[p];
    uint prev_opt_state = table2[opt_state][p];

    /* sanity check */
    if(prev_opt_state >= n_states) {
      log_warn(LD_BUG, "Bug in viterbi: optimal_states index (%u) is out of range "
          "for observation %u/%u",
          prev_opt_state, p-1, n_obs-1);
      goto cleanup; // will return NULL
    }

    optimal_states[p-1] = prev_opt_state;

    log_debug(LD_GENERAL, "Found optimal transition for %u to %u with probability %f",
        prev_opt_state, opt_state, table1[opt_state][p]);
  }

  log_info(LD_GENERAL, "Finished running viterbi. Found optimal path with %u "
      "observations and %f prob. Encoding json result path now.", n_obs, optimal_prob);

  /* convert to json */
  viterbi_json = _encode_viterbi_path(hmm, observations, &optimal_states[0], n_obs);

  log_debug(LD_GENERAL, "Final encoded viterbi path is: %s",
      viterbi_json ? viterbi_json : "NULL");

cleanup:
  tor_assert(table1);
  tor_assert(table2);
  tor_assert(optimal_states);

  for(uint i = 0; i < n_states; i++) {
    tor_assert(table1[i]);
    tor_assert(table2[i]);
    free(table1[i]);
    free(table2[i]);
  }
  free(table1);
  free(table2);
  free(optimal_states);

  return viterbi_json;
}

static void _tmodel_packets_commit_packets(tmodel_packets_t* tpackets,
    int64_t elapsed) {
  tor_assert(tpackets && tpackets->magic == TRAFFIC_MAGIC_PACKETS);

  /* do nothing if we have no packets */
  if (tpackets->buf_length <= 0) {
    return;
  }

  /* all but the last packet have no delay until the following packet */
  while (tpackets->buf_length > TMODEL_PACKET_BYTE_COUNT) {
    /* consecutive packets have no delay */
    tmodel_delay_t d;
    d.delay = 0;
    d.otype = tpackets->buf_obstype;
    void* element;
    memmove(&element, &d, sizeof(void*));
    smartlist_add(tpackets->packets, element);

    /* consume the packet length worth of data */
    tpackets->buf_length -= TMODEL_PACKET_BYTE_COUNT;
  }

  /* then the last packet gets assigned all of the elasped delay
   * from when we started 'buffering' until now */
  tmodel_delay_t d;
  d.delay = (elapsed <= 0) ? 0 : (long unsigned int)elapsed;
  d.otype = tpackets->buf_obstype;
  void* element;
  memmove(&element, &d, sizeof(void*));
  smartlist_add(tpackets->packets, element);

  /* all of the buffered data has been committed */
  tpackets->buf_length = 0;
}

void tmodel_packets_observation(tmodel_packets_t* tpackets,
    tmodel_obs_type_t otype, size_t payload_length) {
  tor_assert(tpackets && tpackets->magic == TRAFFIC_MAGIC_PACKETS);

  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return;
  }

  /* make sure we actually have a payload */
  if(otype != TMODEL_OBSTYPE_PACKETS_FINISHED &&
      payload_length == 0) {
    return;
  }

  /* should be a packet-related observation */
  if(otype != TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN &&
      otype != TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN &&
      otype != TMODEL_OBSTYPE_PACKETS_FINISHED) {
    return;
  }

  monotime_t now;
  monotime_get(&now);

  if (tpackets->buf_length > 0) {
    /* check if we need to 'commit' any previously 'buffered' data */
    int64_t elapsed = monotime_diff_usec(&tpackets->buf_time, &now);

    /* we commit previous data if enough time has passed,
     * or the observation type changes */
    if (elapsed >= TMODEL_PACKET_TIME_TOLERENCE ||
        tpackets->buf_obstype != otype) {
      log_debug(LD_GENERAL, "Committing packets of type %i with elapsed %lli, buf type %i",
          (int)otype, (long long int)elapsed, (int)tpackets->buf_obstype);
      _tmodel_packets_commit_packets(tpackets, elapsed);
    }
  }

  /* initialize the buffer if empty */
  if (tpackets->buf_length == 0) {
    tpackets->buf_obstype = otype;
    tpackets->buf_time = now;
  }

  if(otype == TMODEL_OBSTYPE_PACKETS_FINISHED) {
    /* 'commit' the observation */
    tmodel_delay_t d;
    d.delay = 0;
    d.otype = TMODEL_OBSTYPE_PACKETS_FINISHED;
    void* element;
    memmove(&element, &d, sizeof(void*));
    smartlist_add(tpackets->packets, element);
  } else {
    /* start tracking the new data */
    tpackets->buf_length += payload_length;
  }
}

/* allocate storage for a new tmodel stream object that will be used
 * to track cell transmit times while a stream is active. */
tmodel_packets_t* tmodel_packets_new(void) {
  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return NULL;
  }

  /* if we don't want to count a packet model, we don't need to track */
  if(global_traffic_model == NULL || global_traffic_model->hmm_packets == NULL) {
    return NULL;
  }

  tmodel_packets_t* tpackets = tor_malloc_zero_(sizeof(struct tmodel_packets_s));
  tpackets->magic = TRAFFIC_MAGIC_PACKETS;
  num_outstanding_packets++;

  monotime_get(&tpackets->creation_time);

  /* store packet delay times in the element pointers */
  tpackets->packets = smartlist_new();

  return tpackets;
}

static void _tmodel_handle_viterbi_result(char* viterbi_json,
    tmodel_packets_t* tpackets, tmodel_streams_t* tstreams) {
  if(viterbi_json != NULL) {
    /* send the viterbi json result */
    if(tpackets) {
      control_event_privcount_viterbi_packets(viterbi_json);
    } else if(tstreams) {
      control_event_privcount_viterbi_streams(viterbi_json);
    }
    free(viterbi_json);
  } else {
    /* send a json empty list to signal an error */
    char* empty_list = strndup("[]", 2);
    if(tpackets) {
      control_event_privcount_viterbi_packets(empty_list);
    } else if(tstreams) {
      control_event_privcount_viterbi_streams(empty_list);
    }
    free(empty_list);
  }
}

static void _tmodel_packets_free_helper(tmodel_packets_t* tpackets) {
  tor_assert(tpackets && tpackets->magic == TRAFFIC_MAGIC_PACKETS);

  /* the packet data is stored in the packet element pointers,
   * which will be freed by the smartlist. */
  smartlist_free(tpackets->packets);

  tpackets->magic = 0;
  tor_free_(tpackets);

  if(num_outstanding_packets > 0) {
    num_outstanding_packets--;
  }
}

static void _tmodel_streams_free_helper(tmodel_streams_t* tstreams) {
  tor_assert(tstreams && tstreams->magic == TRAFFIC_MAGIC_STREAMS);

  /* the stream data is stored in the packet element pointers,
   * which will be freed by the smartlist. */
  smartlist_free(tstreams->streams);

  tstreams->magic = 0;
  tor_free_(tstreams);

  if(num_outstanding_streams > 0) {
    num_outstanding_streams--;
  }
}

static void _tmodel_process_models(tmodel_packets_t* tpackets,
    tmodel_streams_t* tstreams) {
  /* process a finished stream.
   * run viterbi to get the best HMM path for this stream, and then
   * send the json result string to PrivCount over the control port. */
  int num_workers = get_options()->PrivCountNumViterbiWorkers;
  if(num_workers > 0) {
    /* Run this task in the viterbi worker thread pool.
     * If we started with no workers and then changed the
     * config partway through a collection, we need to
     * make sure the thread pool is initialized (which
     * also would sync the traffic model in the process). */
    _viterbi_workers_init((uint)num_workers);
  }

  if(num_workers > 0 && _viterbi_thread_pool_is_ready()) {
    /* the thread pool will run the task, and the result will get
     * processed and then freed in _viterbi_worker_handle_reply. */
    _viterbi_worker_assign(tpackets, tstreams);
  } else {
    /* just run the task now in the main thread using the main
     * thread instance of the traffic model. */
    if(tpackets && global_traffic_model->hmm_packets) {
      char* viterbi_json = _tmodel_run_viterbi(
          global_traffic_model->hmm_packets, tpackets->packets);

      /* send the appropriate event to PrivCount.
       * after calling this function, viterbi_json is invalid. */
      _tmodel_handle_viterbi_result(viterbi_json, tpackets, NULL);

      /* free the data */
      _tmodel_packets_free_helper(tpackets);
    }

    if(tstreams && global_traffic_model->hmm_streams) {
      char* viterbi_json = _tmodel_run_viterbi(
          global_traffic_model->hmm_streams, tstreams->streams);

      /* send the appropriate event to PrivCount.
       * after calling this function, viterbi_json is invalid. */
      _tmodel_handle_viterbi_result(viterbi_json, NULL, tstreams);

      /* free the data */
      _tmodel_streams_free_helper(tstreams);
    }
  }
}

/* notify the traffic model that the stream closed and should
 * be processed and freed. */
void tmodel_packets_free(tmodel_packets_t* tpackets) {
  tor_assert(tpackets && tpackets->magic == TRAFFIC_MAGIC_PACKETS);

  /* the stream is finished, we have all of the data we are going to get. */
  if (tmodel_is_active()) {
    /* process a finished list of observed packets. */
    _tmodel_process_models(tpackets, NULL);
  } else {
    /* We are no longer active and don't need to process the
     * packet list. Just go ahead and free the memory. */
    _tmodel_packets_free_helper(tpackets);
  }
}

void tmodel_streams_free(tmodel_streams_t* tstreams) {
  tor_assert(tstreams && tstreams->magic == TRAFFIC_MAGIC_STREAMS);

  /* the stream is finished, we have all of the data we are going to get. */
  if (tmodel_is_active()) {
    /* process a finished list of observed packets. */
    _tmodel_process_models(NULL, tstreams);
  } else {
    /* We are no longer active and don't need to process the
     * packet list. Just go ahead and free the memory. */
    _tmodel_streams_free_helper(tstreams);
  }
}

void tmodel_streams_observation(tmodel_streams_t* tstreams,
    tmodel_obs_type_t otype) {
  tor_assert(tstreams && tstreams->magic == TRAFFIC_MAGIC_STREAMS);

  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return;
  }

  /* should be a stream-related observation */
  if(otype != TMODEL_OBSTYPE_STREAM_NEW &&
      otype != TMODEL_OBSTYPE_STREAMS_FINISHED) {
    return;
  }

  monotime_t now;
  monotime_get(&now);

  if(tstreams->buf_obstype != 0) {
    /* commit the previous stream info */
    int64_t elapsed = monotime_diff_usec(&tstreams->buf_time, &now);
    tmodel_delay_t d;
    d.delay = (elapsed <= 0) ? 0 : (long unsigned int)elapsed;
    d.otype = tstreams->buf_obstype;
    void* element;
    memmove(&element, &d, sizeof(void*));
    smartlist_add(tstreams->streams, element);
  }

  tstreams->buf_obstype = otype;
  tstreams->buf_time = now;

  if(otype == TMODEL_OBSTYPE_STREAMS_FINISHED) {
    tmodel_delay_t d;
    d.delay = 0;
    d.otype = TMODEL_OBSTYPE_STREAMS_FINISHED;
    void* element;
    memmove(&element, &d, sizeof(void*));
    smartlist_add(tstreams->streams, element);
  }
}

tmodel_streams_t* tmodel_streams_new(void) {
  /* just in case, don't do unnecessary work */
  if (!tmodel_is_active()) {
    return NULL;
  }

  /* if we don't want to count a stream model, we don't need to track */
  if(global_traffic_model == NULL || global_traffic_model->hmm_streams == NULL) {
    return NULL;
  }

  tmodel_streams_t* tstreams = tor_malloc_zero_(sizeof(struct tmodel_streams_s));
  tstreams->magic = TRAFFIC_MAGIC_STREAMS;
  num_outstanding_streams++;

  monotime_get(&tstreams->creation_time);

  /* store stream delay times in the element pointers */
  tstreams->streams = smartlist_new();

  return tstreams;
}

/******************************
 ** Viterbi work thread code **
 ******************************/

static replyqueue_t* viterbi_reply_queue = NULL;
static threadpool_t* viterbi_thread_pool = NULL;
static struct event* viterbi_reply_event = NULL;

typedef struct viterbi_worker_state_s {
  tmodel_t* thread_traffic_model;
} viterbi_worker_state_t;

typedef struct viterbi_worker_job_s {
  tmodel_packets_t* tpackets;
  tmodel_streams_t* tstreams;
  char* viterbi_result;
} viterbi_worker_job_t;

static viterbi_worker_job_t* _viterbi_job_new(
    tmodel_packets_t* tpackets, tmodel_streams_t* tstreams) {
  viterbi_worker_job_t* job = calloc(1, sizeof(viterbi_worker_job_t));
  job->tpackets = tpackets;
  job->tstreams = tstreams;
  num_outstanding_jobs++;
  return job;
}

static void _viterbi_job_free(viterbi_worker_job_t* job) {
  if(job) {
    if(job->tpackets) {
      _tmodel_packets_free_helper(job->tpackets);
    }
    if(job->tstreams) {
      _tmodel_streams_free_helper(job->tstreams);
    }
    if(job->viterbi_result) {
      free(job->viterbi_result);
    }
    free(job);
    if(num_outstanding_jobs > 0) {
      num_outstanding_jobs--;
    }
  }
}

static int _viterbi_thread_pool_is_ready(void) {
  return viterbi_thread_pool ? 1 : 0;
}

/* this function is run in a worker thread */
static workqueue_reply_t _viterbi_worker_work_threadfn(void* state_arg, void* job_arg) {
  viterbi_worker_state_t* state = state_arg;
  viterbi_worker_job_t* job = job_arg;

  if(!state) {
    log_warn(LD_BUG, "Viterbi worker state is NULL in work function.");
  }

  if(!job) {
    log_warn(LD_BUG, "Viterbi worker job is NULL in work function.");
  }

  if(!job->tpackets && !job->tstreams) {
    log_warn(LD_BUG, "Viterbi worker packets and streams are both NULL in work function.");
  }

  /* its OK if the traffic model is NULL, it means we synced with
   * a NULL model while we still had jobs to finish */
  if(state && state->thread_traffic_model && job &&
      (job->tpackets || job->tstreams)) {
    /* if we make it here, we can run the viterbi algorithm.
     * The result will be stored in the job object, and handled
     * by the main thread in the handle_reply function. */
    if(job->tpackets && state->thread_traffic_model->hmm_packets) {
      job->viterbi_result = _tmodel_run_viterbi(
          state->thread_traffic_model->hmm_packets, job->tpackets->packets);
    } else if(job->tstreams && state->thread_traffic_model->hmm_streams) {
      job->viterbi_result = _tmodel_run_viterbi(
          state->thread_traffic_model->hmm_streams, job->tstreams->streams);
    }
  }

  return WQ_RPL_REPLY;
}

/* Handle a reply from the worker threads.
 * This function is run in the main thread. */
static void _viterbi_worker_handle_reply(void* job_arg) {
  viterbi_worker_job_t* job = job_arg;
  if(job) {
    /* count the result, and free the string. */
    _tmodel_handle_viterbi_result(job->viterbi_result, job->tpackets, job->tstreams);
    /* the above frees the string, so don't double free */
    job->viterbi_result = NULL;
    /* free the job */
    _viterbi_job_free(job);
  } else {
    log_warn(LD_BUG, "Viterbi job is NULL in reply.");
  }
}

/* Pass the stream as a job for the thread pool.
 * This function is run in the main thread. */
static void _viterbi_worker_assign_job(viterbi_worker_job_t* job) {
  /* queue the job in the thread pool */
  workqueue_entry_t* queue_entry = threadpool_queue_work(viterbi_thread_pool,
      _viterbi_worker_work_threadfn, _viterbi_worker_handle_reply, job);

  if(!queue_entry) {
    log_warn(LD_BUG, "Unable to queue work on viterbi thread pool.");
    /* count this as a failure */
    _tmodel_handle_viterbi_result(NULL, job->tpackets, job->tstreams);
    /* free the job */
    _viterbi_job_free(job);
  }
}

/* Create a job for the thread pool.
 * This function is run in the main thread. */
static void _viterbi_worker_assign(tmodel_packets_t* tpackets,
    tmodel_streams_t* tstreams) {
  /* create job that has the stream in it */
  viterbi_worker_job_t* job = _viterbi_job_new(tpackets, tstreams);
  _viterbi_worker_assign_job(job);
}

/* this function is run in a worker thread */
static void _viterbi_worker_log_model(tmodel_hmm_t* hmm, const char* name) {
  if(hmm) {
    log_notice(LD_GENERAL, "Successfully copied traffic %s model "
              "with %u states in the state_space, %u actions in the "
              "in the observation_space, and %u possible transitions "
              "for a thread",
              name, hmm->num_states, hmm->num_obs,
              hmm->num_states*hmm->num_states);
  }
}

/* this function is run in a worker thread */
static void * _viterbi_worker_state_new(void *arg) {
  (void) arg;

  viterbi_worker_state_t* state = tor_malloc_zero(sizeof(viterbi_worker_state_t));

  /* we need to reference the global traffic model here
   * to make sure we have the latest version. */
  tor_mutex_acquire(global_traffic_model_lock);
  if(global_traffic_model) {
    state->thread_traffic_model = _tmodel_deepcopy(global_traffic_model);
  }
  tor_mutex_release(global_traffic_model_lock);

  if(state->thread_traffic_model){
    if(state->thread_traffic_model->hmm_packets) {
      _viterbi_worker_log_model(state->thread_traffic_model->hmm_packets, "packet");
    }
    if(state->thread_traffic_model->hmm_streams) {
      _viterbi_worker_log_model(state->thread_traffic_model->hmm_streams, "stream");
    }
  } else {
    log_notice(LD_GENERAL, "Setting traffic model for a thread to NULL");
  }

  return state;
}

/* this function is run in a worker thread */
static void _viterbi_worker_state_free(void *arg) {
  viterbi_worker_state_t* state = arg;

  if(state) {
    if(state->thread_traffic_model) {
      _tmodel_free(state->thread_traffic_model);
    }

    tor_free(state);
  }
}

/* this function is run in a worker thread */
static workqueue_reply_t _viterbi_worker_update_threadfn(void* cur, void* upd) {
  viterbi_worker_state_t* current_state = cur;
  viterbi_worker_state_t* update_state = upd;

  if(current_state->thread_traffic_model) {
    _tmodel_free(current_state->thread_traffic_model);
    current_state->thread_traffic_model = NULL;
  }

  if (update_state->thread_traffic_model) {
    current_state->thread_traffic_model = update_state->thread_traffic_model;
    update_state->thread_traffic_model = NULL;
  }

  _viterbi_worker_state_free(update_state);

  return WQ_RPL_REPLY;
}

/* callback invoked by libevent when replies are waiting in
 * in the reply queue. */
static void _viterbi_reply_queue_readable_cb(evutil_socket_t sock, short events, void *arg) {
  replyqueue_t *rq = arg;
  (void) sock;
  (void) events;
  /* loops through all replies and calls the reply function,
   * _viterbi_worker_handle_reply, on each reply. */
  replyqueue_process(rq);
}

static void _viterbi_workers_sync(void) {
  if(!viterbi_thread_pool) {
    return;
  }

  log_notice(LD_GENERAL, "Now attempting to queue a traffic model update "
          "on the viterbi threads");

  if (threadpool_queue_update(viterbi_thread_pool, _viterbi_worker_state_new,
      _viterbi_worker_update_threadfn, _viterbi_worker_state_free, NULL) < 0) {
    log_warn(LD_GENERAL,
        "Failed to queue traffic model update for viterbi worker threads.");
  } else {
    log_notice(LD_GENERAL, "Successfully queued a traffic model update "
        "on the viterbi threads");
  }
}

static int _viterbi_workers_init(uint num_workers) {
  if (!viterbi_reply_queue) {
    viterbi_reply_queue = replyqueue_new(0);
  }

  if (!viterbi_reply_event) {
    viterbi_reply_event = tor_event_new(tor_libevent_get_base(),
        replyqueue_get_socket(viterbi_reply_queue), EV_READ | EV_PERSIST,
        _viterbi_reply_queue_readable_cb, viterbi_reply_queue);
    event_add(viterbi_reply_event, NULL);
  }

  if (!viterbi_thread_pool) {
    viterbi_thread_pool = threadpool_new(num_workers, viterbi_reply_queue,
        _viterbi_worker_state_new, _viterbi_worker_state_free, NULL);

    if(viterbi_thread_pool) {
      log_notice(LD_GENERAL, "Successfully created viterbi thread pool "
          "with %u worker threads.", num_workers);
    } else {
      log_warn(LD_GENERAL, "Failed to create viterbi thread pool "
                "with %u worker threads. We will try again soon and"
                "otherwise fall back to running viterbi in the main "
                "thread.", num_workers);
    }

    return 1;
  } else {
    return 0;
  }
}
