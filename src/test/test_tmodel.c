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
    "TRUE {\"packet_model\":{\"observation_space\":[\"+\";\"-\";\"F\"];\"emission_probability\":{\"s1\":{\"+\":[0.1;3.8;1.7;0.0];\"-\":[0.9;1.4;0.9;0.0]};\"s0\":{\"+\":[0.8;12.0;0.01;0.0];\"-\":[0.2;5.5;3.0;0.0]};\"End\":{\"F\":[1.0]}};\"state_space\":[\"s0\";\"s1\";\"End\"];\"transition_probability\":{\"s1\":{\"s0\":0.5;\"End\":0.5};\"s0\":{\"s1\":0.25;\"s0\":0.75};\"End\":{}};\"start_probability\":{\"s1\":0.8;\"s0\":0.2}};\"stream_model\":{\"observation_space\":[\"$\";\"F\"];\"emission_probability\":{\"s2End\":{\"F\":[1.0]};\"s1Dwell\":{\"$\":[1.0;2980957.987041;1.36;0.0]};\"s0Active\":{\"$\":[1.0;0.0;0.0;0.00015]}};\"state_space\":[\"s0Active\";\"s1Dwell\";\"s2End\"];\"transition_probability\":{\"s2End\":{};\"s1Dwell\":{\"s2End\":0.34;\"s1Dwell\":0.495;\"s0Active\":0.165};\"s0Active\":{\"s2End\":0.34;\"s1Dwell\":0.165;\"s0Active\":0.495}};\"start_probability\":{\"s2End\":0.0;\"s1Dwell\":0.5;\"s0Active\":0.5}}}";

// FIXME monotime_coarse_set_mock_time_nsec doesn't seem to be setting a nonzero time
// the true result should be the following
//const char* viterbi_str =
//    "[[\"s1\";\"+\";1000];[\"s0\";\"+\";1000];[\"s0\";\"-\";1000];[\"s1\";\"-\";1000];[\"End\";\"F\";1000]]";
const char* viterbi_packets_str =
  "[[\"s1\";\"+\";0];[\"s0\";\"+\";0];[\"s0\";\"-\";0];[\"s1\";\"-\";0];[\"End\";\"F\";0]]";
const char* viterbi_streams_str =
  "[[\"s0Active\";\"$\";0];[\"s0Active\";\"$\";0];[\"s0Active\";\"$\";0];[\"s2End\";\"F\";0]]";

static void
control_event_privcount_viterbi_mock(char* viterbi_result) {
  tt_assert(viterbi_result != NULL);
done:
  return;
}

static void
control_event_privcount_viterbi_packets_mock(char* viterbi_result) {
  printf("Viterbi result\n%s\n", viterbi_result ? viterbi_result : "[]");
  tt_assert(viterbi_result != NULL);
  int str_result_comp = strncasecmp(viterbi_result,
      viterbi_packets_str, strlen(viterbi_packets_str));
  tt_assert(str_result_comp == 0);
done:
  return;
}

static void
control_event_privcount_viterbi_streams_mock(char* viterbi_result) {
  printf("Viterbi result\n%s\n", viterbi_result ? viterbi_result : "[]");
  tt_assert(viterbi_result != NULL);
  int str_result_comp = strncasecmp(viterbi_result,
      viterbi_streams_str, strlen(viterbi_streams_str));
  tt_assert(str_result_comp == 0);
done:
  return;
}

/* Event base for scheduler tests */
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

  MOCK(control_event_privcount_viterbi_packets,
      control_event_privcount_viterbi_mock);
  MOCK(control_event_privcount_viterbi_streams,
      control_event_privcount_viterbi_mock);

  mock_event_init();
  MOCK(tor_libevent_get_base, tor_libevent_get_base_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_streams_t* test_circuit = tmodel_streams_new();
  tt_assert(test_circuit);

  for(int i = 0; i < 1000; i++) {
    uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
    monotime_coarse_set_mock_time_nsec(now_ns);

    tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

    tmodel_packets_t* test_stream = tmodel_packets_new();
    tt_assert(test_stream);

    for(int j = 0; j < 10000; j++) {
      tmodel_packets_observation(test_stream,
          TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN, 1434);
      tmodel_packets_observation(test_stream,
          TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN, 1434);
    }

    tmodel_packets_observation(test_stream,
        TMODEL_OBSTYPE_PACKETS_FINISHED, 0);
    tmodel_packets_free(test_stream);

    /* run the loop so we process thread result */
    result = event_base_loop(tor_libevent_get_base_mock(), EVLOOP_ONCE);
    tt_assert(result >= 0);
  }

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAMS_FINISHED);
  tmodel_streams_free(test_circuit);

  result = tmodel_set_traffic_model((uint32_t) 0, NULL);
  tt_assert(result == 0);

done:
  mock_event_free_all();
  UNMOCK(tor_libevent_get_base);
  UNMOCK(control_event_privcount_viterbi_packets);
  UNMOCK(control_event_privcount_viterbi_streams);
  monotime_disable_test_mocking();
  return;
}

static void
test_traffic_model_viterbi_packets(void *arg) {
  (void) arg;
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = 0;

  uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(now_ns);

  MOCK(control_event_privcount_viterbi_packets,
      control_event_privcount_viterbi_packets_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_packets_t* test_stream = tmodel_packets_new();
  tt_assert(test_stream);

  /* now simulate some packets getting transferred */
  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKETS_FINISHED, 0);

  /* close the stream, which runs viterbi */

  tmodel_packets_free(test_stream);

done:
  UNMOCK(control_event_privcount_viterbi_packets);
  monotime_disable_test_mocking();
  return;
}

static void
test_traffic_model_viterbi_streams(void *arg) {
  (void) arg;
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = 0;

  uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
  monotime_enable_test_mocking();
  monotime_coarse_set_mock_time_nsec(now_ns);

  MOCK(control_event_privcount_viterbi_streams,
      control_event_privcount_viterbi_streams_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_streams_t* test_circuit = tmodel_streams_new();
  tt_assert(test_circuit);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

  now_ns += 1000 * 1000;
  monotime_coarse_set_mock_time_nsec(now_ns);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);
  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAMS_FINISHED);

  tmodel_streams_free(test_circuit);

done:
  UNMOCK(control_event_privcount_viterbi_streams);
  monotime_disable_test_mocking();
  return;
}

struct testcase_t tmodel_tests[] = {
  { "parse", test_traffic_model_parse, TT_FORK, NULL, NULL },
  { "viterbi_packets", test_traffic_model_viterbi_packets, TT_FORK, NULL, NULL },
  { "viterbi_streams", test_traffic_model_viterbi_streams, TT_FORK, NULL, NULL },
  { "viterbi_threads", test_traffic_model_viterbi_threads, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
