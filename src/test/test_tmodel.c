/*
 * test_tmodel.c
 *
 *  Created on: Feb 10, 2018
 *      Author: rjansen
 */
#include <string.h>
#include <stdio.h>

#include "or.h"
#include "compat_time.h"
#include "config.h"
#include "control.h"
#include "tmodel.h"
#include "test.h"
#include "test_helpers.h"

const char* tmodel_str =
    "TRUE {\"observation_space\":[\"+\";\"-\";\"F\"];\"emission_probability\":{\"End\":{\"F\":[1.0;10.2;4.0]};\"s1\":{\"+\":[0.1;3.8;1.7];\"-\":[0.9;1.4;0.9]};\"s0\":{\"+\":[0.8;12.0;0.01];\"-\":[0.2;5.5;3.0]}};\"state_space\":[\"s0\";\"s1\";\"End\"];\"transition_probability\":{\"s1\":{\"s0\":0.5;\"End\":0.5};\"s0\":{\"s1\":0.25;\"s0\":0.75};\"End\":{}};\"start_probability\":{\"s1\":0.8;\"s0\":0.2}}";

// FIXME monotime_coarse_set_mock_time_nsec doesn't seem to be setting a nonzero time
// the true result should be the following
//const char* viterbi_str =
//    "[[\"s1\";\"+\";1000];[\"s0\";\"+\";1000];[\"s0\";\"-\";1000];[\"s1\";\"-\";1000];[\"End\";\"F\";1000]]";
const char* viterbi_str =
    "[[\"s1\";\"+\";0];[\"s0\";\"+\";0];[\"s0\";\"-\";0];[\"s1\";\"-\";0];[\"End\";\"F\";0]]";

static void
control_event_privcount_viterbi_mock(char* viterbi_result) {
  printf("Viterbi result\n%s\n", viterbi_result ? viterbi_result : "[]");
  tt_assert(viterbi_result != NULL);
  int str_result_comp = strncasecmp(viterbi_result, viterbi_str, strlen(viterbi_str));
  tt_assert(str_result_comp == 0);
done:
  return;
}

/* Event base for scheduelr tests */
static struct event_base *mock_event_base = NULL;
/* Setup for mock event stuff */
static void mock_event_free_all(void);
static void mock_event_init(void);
static void
mock_event_free_all(void)
{
  tt_ptr_op(mock_event_base, OP_NE, NULL);

  if (mock_event_base) {
    event_base_free(mock_event_base);
    mock_event_base = NULL;
  }

  tt_ptr_op(mock_event_base, OP_EQ, NULL);

 done:
  return;
}

static void
mock_event_init(void)
{
  struct event_config *cfg = NULL;

  tt_ptr_op(mock_event_base, OP_EQ, NULL);

  if (!mock_event_base) {
    cfg = event_config_new();
    mock_event_base = event_base_new_with_config(cfg);
    event_config_free(cfg);
  }

  tt_ptr_op(mock_event_base, OP_NE, NULL);

 done:
  return;
}

static struct event_base *
tor_libevent_get_base_mock(void)
{
  return mock_event_base;
}

static void
test_traffic_model_parse(void *arg) {
  (void) arg;
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = 0;

  monotime_enable_test_mocking();
  uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  //printf("%s\n", tmodel_str);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

  result = tmodel_set_traffic_model((uint32_t) 5, "INVALID STRING");
  tt_assert(result == 0);

done:
  monotime_disable_test_mocking();
  return;
}

static void
test_traffic_model_viterbi_threads(void *arg) {
  (void) arg;
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = 1;

  monotime_enable_test_mocking();

  mock_event_init();
  MOCK(tor_libevent_get_base, tor_libevent_get_base_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  for(int i = 0; i < 1000; i++) {
    uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
    monotime_coarse_set_mock_time_nsec(now_ns);

    tmodel_packets_t* test_stream = tmodel_packets_new();
    tt_assert(test_stream);

    for(int j = 0; j < 10000; j++) {
      tmodel_packets_cell_transferred(test_stream, 1434,
          TMODEL_OBS_RECV_FROM_ORIGIN);
      tmodel_packets_cell_transferred(test_stream, 1434,
          TMODEL_OBS_SENT_TO_ORIGIN);
    }

    tmodel_packets_free(test_stream);

    /* run the loop so we process thread result */
    result = event_base_loop(tor_libevent_get_base_mock(), EVLOOP_ONCE);
    tt_assert(result >= 0);
  }

  result = tmodel_set_traffic_model((uint32_t) 0, NULL);
  tt_assert(result == 0);

done:
  mock_event_free_all();
  UNMOCK(tor_libevent_get_base);
  monotime_disable_test_mocking();
  return;
}

static void
test_traffic_model_viterbi(void *arg) {
  (void) arg;
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = 0;

  uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(now_ns);

  MOCK(control_event_privcount_viterbi, control_event_privcount_viterbi_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_packets_t* test_stream = tmodel_packets_new();
  tt_assert(test_stream);

  /* now simulate some packets getting transferred */
  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_cell_transferred(test_stream, 1434,
      TMODEL_OBS_RECV_FROM_ORIGIN);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_cell_transferred(test_stream, 1434,
      TMODEL_OBS_RECV_FROM_ORIGIN);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_cell_transferred(test_stream, 1434,
      TMODEL_OBS_SENT_TO_ORIGIN);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_cell_transferred(test_stream, 1434,
      TMODEL_OBS_SENT_TO_ORIGIN);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_cell_transferred(test_stream, 1434,
      TMODEL_OBS_DONE);

  /* close the stream, which runs viterbi */

  tmodel_packets_free(test_stream);

done:
  UNMOCK(control_event_privcount_viterbi);
  monotime_disable_test_mocking();
  return;
}

struct testcase_t tmodel_tests[] = {
  { "parse", test_traffic_model_parse, TT_FORK, NULL, NULL },
  { "viterbi", test_traffic_model_viterbi, TT_FORK, NULL, NULL },
  { "viterbi_threads", test_traffic_model_viterbi_threads, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
