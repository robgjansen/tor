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

#define PACKET_MODEL_DICT "{\"observation_space\":[\"+\";\"-\";\"F\"];\"emission_probability\":{\"s1\":{\"+\":[0.1;3.8;1.7;0.0];\"-\":[0.9;1.4;0.9;0.0]};\"s0\":{\"+\":[0.8;12.0;0.01;0.0];\"-\":[0.2;5.5;3.0;0.0]};\"End\":{\"F\":[1.0]}};\"state_space\":[\"s0\";\"s1\";\"End\"];\"transition_probability\":{\"s1\":{\"s0\":0.5;\"End\":0.5};\"s0\":{\"s1\":0.25;\"s0\":0.75};\"End\":{}};\"start_probability\":{\"s1\":0.8;\"s0\":0.2}}"
#define STREAM_MODEL_DICT "{\"observation_space\":[\"$\";\"F\"];\"emission_probability\":{\"s2End\":{\"F\":[1.0]};\"s1Dwell\":{\"$\":[1.0;14.907755;1.36;0.0]};\"s0Active\":{\"$\":[1.0;0.0;0.0;0.00015]}};\"state_space\":[\"s0Active\";\"s1Dwell\";\"s2End\"];\"transition_probability\":{\"s2End\":{};\"s1Dwell\":{\"s2End\":0.34;\"s1Dwell\":0.495;\"s0Active\":0.165};\"s0Active\":{\"s2End\":0.34;\"s1Dwell\":0.165;\"s0Active\":0.495}};\"start_probability\":{\"s2End\":0.0;\"s1Dwell\":0.5;\"s0Active\":0.5}}"
const char* tmodel_str =
    "TRUE {\"packet_model\":"PACKET_MODEL_DICT";\"stream_model\":"STREAM_MODEL_DICT"}";
const char* packet_model_str =
    "TRUE {\"packet_model\":"PACKET_MODEL_DICT"}";
const char* stream_model_str =
    "TRUE {\"stream_model\":"STREAM_MODEL_DICT"}";

const char* viterbi_packets_str =
    "[[\"s1\";\"+\";1000];[\"s0\";\"+\";1000];[\"s0\";\"-\";1000];[\"s1\";\"-\";1000];[\"End\";\"F\";0]]";
const char* viterbi_streams_str =
    "[[\"s0Active\";\"$\";1000];[\"s0Active\";\"$\";1000];[\"s0Active\";\"$\";1000];[\"s2End\";\"F\";0]]";
const char* viterbi_streams_dwell_str =
    "[[\"s1Dwell\";\"$\";2957929];[\"s1Dwell\";\"$\";2957929];[\"s1Dwell\";\"$\";2957929];[\"s1Dwell\";\"$\";2957929];[\"s1Dwell\";\"$\";2957929];[\"s2End\";\"F\";0]]";


static void
control_event_privcount_viterbi_mock(char* viterbi_result) {
  tt_assert(viterbi_result != NULL);
done:
  return;
}

static void
control_event_privcount_viterbi_dwell_mock(char* viterbi_result) {
  printf("Viterbi result\n%s\n", viterbi_result ? viterbi_result : "[]");
  tt_assert(viterbi_result != NULL);
  int str_result_comp = strncasecmp(viterbi_result,
      viterbi_streams_dwell_str, strlen(viterbi_streams_dwell_str));
  tt_assert(str_result_comp == 0);
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

static uint64_t test_traffic_model_common_setup_helper(int num_threads,
    void* packets_mock, void* streams_mock) {
  or_options_t *options = get_options_mutable();
  options->EnablePrivCount = 1;
  options->PrivCountNumViterbiWorkers = num_threads;

  monotime_enable_test_mocking();

  MOCK(control_event_privcount_viterbi_packets, packets_mock);
  MOCK(control_event_privcount_viterbi_streams, streams_mock);

  mock_event_init();
  MOCK(tor_libevent_get_base, tor_libevent_get_base_mock);

  uint64_t now_ns = 1389631048 * (uint64_t) 1000000000;
  monotime_set_mock_time_nsec(now_ns);
  return now_ns;
}

static uint64_t test_traffic_model_common_setup(int num_threads) {
  return test_traffic_model_common_setup_helper(num_threads,
      control_event_privcount_viterbi_packets_mock,
      control_event_privcount_viterbi_streams_mock);
}

static void test_traffic_model_common_teardown(void) {
  mock_event_free_all();
  UNMOCK(tor_libevent_get_base);
  UNMOCK(control_event_privcount_viterbi_packets);
  UNMOCK(control_event_privcount_viterbi_streams);
  monotime_disable_test_mocking();
}

static void
test_traffic_model_parse_helper(const char* model_str, int num_threads) {
  test_traffic_model_common_setup(num_threads);

  uint32_t model_str_len = (uint32_t) strlen(model_str);
  int result = tmodel_set_traffic_model(model_str_len, model_str);
  tt_assert(result == 0);

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

  result = tmodel_set_traffic_model((uint32_t) 5, "INVALID STRING");
  tt_assert(result == 0);

done:
  test_traffic_model_common_teardown();
  return;
}

static void
test_traffic_model_parse_full(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(tmodel_str, 0);
}

static void
test_traffic_model_parse_full_threads(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(tmodel_str, 1);
}

static void
test_traffic_model_parse_stream_only(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(stream_model_str, 0);
}

static void
test_traffic_model_parse_stream_only_threads(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(stream_model_str, 1);
}

static void
test_traffic_model_parse_packet_only(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(packet_model_str, 0);
}

static void
test_traffic_model_parse_packet_only_threads(void *arg) {
  (void) arg;
  test_traffic_model_parse_helper(packet_model_str, 1);
}

static void
test_traffic_model_viterbi_packets_helper(const char* model_str, int num_threads) {
  uint64_t now_ns = test_traffic_model_common_setup(num_threads);

  uint32_t model_str_len = (uint32_t) strlen(model_str);
  int result = tmodel_set_traffic_model(model_str_len, model_str);
  tt_assert(result == 0);

  tmodel_packets_t* test_stream = tmodel_packets_new();
  tt_assert(test_stream);

  /* now simulate some packets getting transferred */
  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_RECV_FROM_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKET_SENT_TO_ORIGIN, 1434);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_packets_observation(test_stream,
      TMODEL_OBSTYPE_PACKETS_FINISHED, 0);

  /* close the stream, which runs viterbi */

  tmodel_packets_free(test_stream);

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

done:
  test_traffic_model_common_teardown();
  return;
}

static void
test_traffic_model_viterbi_packets_full(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_packets_helper(tmodel_str, 0);
}

static void
test_traffic_model_viterbi_packets_full_threads(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_packets_helper(tmodel_str, 1);
}

static void
test_traffic_model_viterbi_packets_packets(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_packets_helper(packet_model_str, 0);
}

static void
test_traffic_model_viterbi_packets_packets_threads(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_packets_helper(packet_model_str, 1);
}

static void
test_traffic_model_viterbi_streams_helper(const char* model_str, int num_threads) {
  uint64_t now_ns = test_traffic_model_common_setup(num_threads);

  int result = tmodel_set_traffic_model((uint32_t) strlen(model_str),
      model_str);
  tt_assert(result == 0);

  tmodel_streams_t* test_circuit = tmodel_streams_new();
  tt_assert(test_circuit);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

  now_ns += 1000 * 1000;
  monotime_set_mock_time_nsec(now_ns);

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAMS_FINISHED);

  tmodel_streams_free(test_circuit);

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

done:
  test_traffic_model_common_teardown();
  return;
}

static void
test_traffic_model_viterbi_streams_full(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_streams_helper(tmodel_str, 0);
}

static void
test_traffic_model_viterbi_streams_full_threads(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_streams_helper(tmodel_str, 1);
}

static void
test_traffic_model_viterbi_streams_streams(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_streams_helper(stream_model_str, 0);
}

static void
test_traffic_model_viterbi_streams_streams_threads(void *arg) {
  (void) arg;
  test_traffic_model_viterbi_streams_helper(stream_model_str, 1);
}

static void
test_traffic_model_viterbi_heavy_threads(void *arg) {
  (void) arg;

  void* model_no_check_mock = control_event_privcount_viterbi_mock;
  test_traffic_model_common_setup_helper(1,
      model_no_check_mock, model_no_check_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_streams_t* test_circuit = tmodel_streams_new();
  tt_assert(test_circuit);

  for(int i = 0; i < 1000; i++) {
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

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

done:
  test_traffic_model_common_teardown();
  return;
}

static void
test_traffic_model_viterbi_streams_dwell(void *arg) {
  (void) arg;

  uint64_t now_ns = test_traffic_model_common_setup_helper(0,
      control_event_privcount_viterbi_mock,
      control_event_privcount_viterbi_dwell_mock);

  int result = tmodel_set_traffic_model((uint32_t) strlen(tmodel_str),
      tmodel_str);
  tt_assert(result == 0);

  tmodel_streams_t* test_circuit = tmodel_streams_new();
  tt_assert(test_circuit);


  for(int i = 0; i < 5; i++) {
    tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAM_NEW);

    now_ns += ((uint64_t)1000) * ((uint64_t)2957929); // should cause dwell state
    monotime_set_mock_time_nsec(now_ns);
  }

  tmodel_streams_observation(test_circuit, TMODEL_OBSTYPE_STREAMS_FINISHED);
  tmodel_streams_free(test_circuit);

  result = tmodel_set_traffic_model((uint32_t) 5, "FALSE");
  tt_assert(result == 0);

done:
  test_traffic_model_common_teardown();
  return;
}

struct testcase_t tmodel_tests[] = {
  { "parse_full", test_traffic_model_parse_full, TT_FORK, NULL, NULL },
  { "parse_streams", test_traffic_model_parse_stream_only, TT_FORK, NULL, NULL },
  { "parse_packets", test_traffic_model_parse_packet_only, TT_FORK, NULL, NULL },

  { "parse_full_threads", test_traffic_model_parse_full_threads, TT_FORK, NULL, NULL },
  { "parse_streams_threads", test_traffic_model_parse_stream_only_threads, TT_FORK, NULL, NULL },
  { "parse_packets_threads", test_traffic_model_parse_packet_only_threads, TT_FORK, NULL, NULL },

  { "viterbi_streams_streams", test_traffic_model_viterbi_streams_streams, TT_FORK, NULL, NULL },
  { "viterbi_streams_full", test_traffic_model_viterbi_streams_full, TT_FORK, NULL, NULL },

  { "viterbi_streams_streams_threads", test_traffic_model_viterbi_streams_streams_threads, TT_FORK, NULL, NULL },
  { "viterbi_streams_full_threads", test_traffic_model_viterbi_streams_full_threads, TT_FORK, NULL, NULL },

  { "viterbi_packets_packets", test_traffic_model_viterbi_packets_packets, TT_FORK, NULL, NULL },
  { "viterbi_packets_full", test_traffic_model_viterbi_packets_full, TT_FORK, NULL, NULL },

  { "viterbi_packets_packets_threads", test_traffic_model_viterbi_packets_packets_threads, TT_FORK, NULL, NULL },
  { "viterbi_packets_full_threads", test_traffic_model_viterbi_packets_full_threads, TT_FORK, NULL, NULL },

  { "viterbi_heavy_threads", test_traffic_model_viterbi_heavy_threads, TT_FORK, NULL, NULL },
  { "viterbi_stream_dwell", test_traffic_model_viterbi_streams_dwell, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
