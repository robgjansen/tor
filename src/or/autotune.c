#include "or.h"
#include "autotune.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitmux.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "main.h"
#include "relay.h"

static smartlist_t *pending_write_connection_lst = NULL;
static struct event *global_write_event = NULL;
static int global_write_event_is_pending = 0;
static autotune_t autotune;
static int autotune_initialized = 0;

static double timediff_seconds(struct timespec* begin, struct timespec* end) {
  if (end->tv_nsec < begin->tv_nsec) {
    int n = (begin->tv_nsec - end->tv_nsec) / 1000000000 + 1;
    begin->tv_nsec -= 1000000000 * n;
    begin->tv_sec += n;
  }
  if (end->tv_nsec - begin->tv_nsec > 1000000000) {
    int n = (end->tv_nsec - begin->tv_nsec) / 1000000000;
    begin->tv_nsec += 1000000000 * n;
    begin->tv_sec -= n;
  }

  double sec = (double) (end->tv_sec - begin->tv_sec);
  double nsec = (double) (end->tv_nsec - begin->tv_nsec);
  return (sec + (nsec / 1000000000.0f));
}

//static int
//compare_time_spec(const struct timespec* t1, const struct timespec* t2) {
//  if (t1->tv_sec < t2->tv_sec)
//    return -1;
//  else if (t1->tv_sec > t2->tv_sec)
//    return 1;
//  else {
//    if (t1->tv_nsec < t2->tv_nsec)
//      return -1;
//    else if (t1->tv_nsec > t2->tv_nsec)
//      return 1;
//    else
//      return 0;
//  }
//}

void socket_stats_unref(socket_stats_t *stats) {
  if(stats && --stats->refcount == 0) {
    tor_free(stats);
  }
}

static socket_stats_t*
gather_socket_stats(connection_t *conn) {
  socklen_t sockopt_len;
  socket_stats_t *newstats = tor_malloc(sizeof(socket_stats_t));
  newstats->refcount = 1;

#ifdef TCP_INFO
  sockopt_len = sizeof(struct tcp_info);
  if (getsockopt(conn->s, SOL_TCP, TCP_INFO,
                 (void *)&newstats->tcpi, &sockopt_len) < 0) {
    log_warn(LD_GENERAL, "Failed to obtain TCP INFO for socket %d: %s",
             conn->s,
             strerror(errno));
    socket_stats_unref(newstats);
    return NULL;
  }
#endif

  sockopt_len = sizeof(uint32_t);
  if (getsockopt(conn->s, SOL_SOCKET, SO_SNDBUF,
      &newstats->sndbuflen,&sockopt_len) < 0) {
    log_warn(LD_GENERAL, "Failed to obtain SNDBUF for socket %d: %s",
             conn->s,
             strerror(errno));
    socket_stats_unref(newstats);
    return NULL;
  }

  sockopt_len = sizeof(uint32_t);
  if (getsockopt(conn->s, SOL_SOCKET, SO_RCVBUF,
      &newstats->rcvbuflen,&sockopt_len) < 0) {
    log_warn(LD_GENERAL, "Failed to obtain RCVBUF for socket %d: %s",
             conn->s,
             strerror(errno));
    socket_stats_unref(newstats);
    return NULL;
  }

#ifdef IOCTL_INQ
  sockopt_len = sizeof(uint32_t);
  if (ioctl(conn->s, IOCTL_INQ, &newstats->inqlen) < 0) {
    log_warn(LD_GENERAL, "Failed to obtain INQLEN for socket %d: %s",
             conn->s,
             strerror(errno));
    socket_stats_unref(newstats);
    return NULL;
  }
#endif

#ifdef IOCTL_OUTQ
  sockopt_len = sizeof(uint32_t);
  if (ioctl(conn->s, IOCTL_OUTQ, &newstats->outqlen) < 0) {
    log_warn(LD_GENERAL, "Failed to obtain OUTQLEN for socket %d: %s",
             conn->s,
             strerror(errno));
    socket_stats_unref(newstats);
    return NULL;
  }
#endif

  tor_gettimeofday_cached(&newstats->ts);

  return newstats;
}

//static int
//compare_ack_records(const void *p1, const void *p2)
//{
//  const autotune_ack_t *a1=p1, *a2=p2;
//  return compare_time_spec(&a1->t, &a2->t);
//}

static size_t global_autotune_predict_flushable(or_connection_t* orc) {
  // TODO: consider connection_bucket_write_limit(); ?

//  /* track our ack times */
//  if(!orc->autotune.expected_acks) {
//    orc->autotune.expected_acks = smartlist_new();
//  }
//  /* update calculated rtt */
//  u_int32_t rtt =  orc->autotune.currstats->tcpi.tcpi_rtt;
//  if(orc->autotune.rttmin_nsec == 0 || rtt < orc->autotune.rttmin_nsec) {
//    orc->autotune.rttmin_nsec = ((size_t)rtt) * ((size_t)1000000);
//  }
//
//  /* check our ack predictions */
//  while(smartlist_len(orc->autotune.expected_acks) > 0) {
//    autotune_ack_t* ack = smartlist_get(orc->autotune.expected_acks, 0);
//    tor_assert(ack);
//
//    if(compare_time_spec(&ack->t, &autotune.now.time) >= 0) {
//      ack = smartlist_pqueue_pop(orc->autotune.expected_acks, compare_ack_records,
//          STRUCT_OFFSET(autotune_ack_t, heap_index));
//      /* based on our RTT, we think some acks will be coming within a millisecond */
//      orc->autotune.predicted_acks_coming_soon += ((ssize_t)ack->n);
//      log_info(LD_GENERAL, "autotunetest: ack prediction increased by %u", (unsigned int)ack->n);
//      tor_free(ack);
//      continue;
//    } else {
//      break;
//    }
//  }
//
//  u_int32_t unacked = orc->autotune.currstats->tcpi.tcpi_unacked;
//  u_int32_t last_unacked = orc->autotune.prevstats ? orc->autotune.prevstats->tcpi.tcpi_unacked : 0;
//  ssize_t change = ((ssize_t)unacked) - ((ssize_t)(last_unacked));
//
//  if(change > 0) {
//    /* some new packets were sent - track when we expect the acks to return */
//    autotune_ack_t* ack_rec = tor_calloc(1, sizeof(autotune_ack_t));
//    ack_rec->n = (u_int32_t)change;
//    ack_rec->t = autotune.now.time;
//
//    /* predict time to a millisecond before we expect to receive the acks */
//    size_t nsec = ((size_t)ack_rec->t.tv_nsec) + orc->autotune.rttmin_nsec - 1000000;
//    while(nsec > ((size_t)1000000000)) {
//      ack_rec->t.tv_sec += 1;
//      nsec -= ((size_t)1000000000);
//    }
//    ack_rec->t.tv_nsec = (__syscall_slong_t)nsec;
//
//    smartlist_pqueue_add(orc->autotune.expected_acks, compare_ack_records,
//      STRUCT_OFFSET(autotune_ack_t, heap_index), ack_rec);
//
//    log_info(LD_GENERAL, "autotunetest: sent %u more packets", (unsigned int)ack_rec->n);
//  } else if(change < 0) {
//    /* we actually got some acks, so we should no longer predict that we will get those soon
//     * if this makes predicted_acks_coming_soon negative, then we got the acks before we predicted */
//    orc->autotune.predicted_acks_coming_soon += change;
//    log_info(LD_GENERAL, "autotunetest: got %d more acks", -((int)change));
//  }
//
//  /* now set the limit */
//  ssize_t length = (ssize_t) orc->autotune.currstats->outqlen;
//  ssize_t mss = (ssize_t)orc->autotune.currstats->tcpi.tcpi_snd_mss;
//  ssize_t cngwnd = (ssize_t) orc->autotune.currstats->tcpi.tcpi_snd_cwnd;
//
//  /* dont include in-flight packets */
//  ssize_t predicted_unacked = ((ssize_t)unacked);
//  if(orc->autotune.predicted_acks_coming_soon > 0) {
//    predicted_unacked -= orc->autotune.predicted_acks_coming_soon;
//  }
//  if(predicted_unacked < 0) {
//    predicted_unacked = 0;
//  }
//  ssize_t limit = (cngwnd - predicted_unacked)*mss;
//
//  u_int32_t last_cngwnd = orc->autotune.prevstats ? orc->autotune.prevstats->tcpi.tcpi_snd_cwnd : 0;
//  log_info(LD_GENERAL, "autotunetest: cngwnd=%u last=%u unacked=%u last=%u predicted=%ld limit=%lu",
//      (unsigned int)cngwnd, (unsigned int)last_cngwnd,
//      (unsigned int)unacked, (unsigned int)last_unacked,
//      (long int)orc->autotune.predicted_acks_coming_soon, limit > 0 ? (unsigned long)limit : 0);

  ssize_t length = (ssize_t) orc->autotune.currstats->outqlen;
  ssize_t capacity = (ssize_t) orc->autotune.currstats->sndbuflen;
  ssize_t socket_space = capacity - length;

  ssize_t mss = (ssize_t) orc->autotune.currstats->tcpi.tcpi_snd_mss;
  ssize_t cngwnd = (ssize_t) orc->autotune.currstats->tcpi.tcpi_snd_cwnd;
  ssize_t unacked = (ssize_t) orc->autotune.currstats->tcpi.tcpi_unacked;
  ssize_t tcp_space = (cngwnd-unacked)*mss;
  //ssize_t tcp_space = (cngwnd*mss)-length;

  ssize_t limit = MIN(socket_space, tcp_space);

  log_info(LD_GENERAL, "autotune: conn=%i tcp_space="I64_FORMAT" socket_space="I64_FORMAT" limit="I64_FORMAT,
      (int)TO_CONN(orc)->s, (long long int)tcp_space, (long long int)socket_space, (long long int) limit);

  return (size_t) MAX(limit, 0);
}

/* shadow intercepts this function, so dont change the signature */
double global_autotune_get_write_speed() {
  if(get_options()->AutotuneWriteBWOverride) {
    return (double)get_options()->AutotuneWriteBWOverride;
  } else {
    double total_now_before_write = (double) autotune.now.total;

    double written_last = (double) (autotune.last.written_to_kernel);
    double total_last_after_write = (double) autotune.last.total + written_last;

    double bytes = total_last_after_write - total_now_before_write;
    double secs = timediff_seconds(&autotune.last.time, &autotune.now.time);

    return bytes / secs;
  }
}

static void global_autotune_preupdate() {
  autotune.last = autotune.now;
  memset(&autotune.now, 0, sizeof(autotune_bytes_t));
  clock_gettime(CLOCK_MONOTONIC, &autotune.now.time);
}

static void global_autotune_conn_update(or_connection_t* orc) {
  /* track conn stats */
  if (orc->autotune.prevstats) {
    socket_stats_unref(orc->autotune.prevstats);
  }
  orc->autotune.prevstats = orc->autotune.currstats;
  orc->autotune.currstats = gather_socket_stats(TO_CONN(orc));
  tor_assert(orc->autotune.currstats);

  /* count all the bytes actually sitting in the kernel queue right now */
  autotune.now.total += (size_t) orc->autotune.currstats->outqlen;

  /* only count flushable bytes if we will actually try to write to this conn */
  if(orc->globalSchedulePending) {
    /* compute flushable bytes */
    size_t flushable = global_autotune_predict_flushable(orc);
    orc->autotune.remaining = flushable;
    orc->autotune.kernel_would_flush = flushable;
    autotune.now.kernel_would_flush += flushable;
  } else {
    orc->autotune.kernel_would_flush = 0;
    orc->autotune.remaining = 0;
  }

  log_info(LD_GENERAL, "autotune: conn=%i total="U64_FORMAT" kernel_would_flush="U64_FORMAT" is_pending=%i",
      TO_CONN(orc)->s,
      ((long long unsigned int)orc->autotune.currstats->outqlen),
      ((long long unsigned int)orc->autotune.kernel_would_flush),
      orc->globalSchedulePending);
}

static void global_autotune_postupdate() {
  /* track our max write speed ever seen */
  double bytesPerSec = global_autotune_get_write_speed();
  if (bytesPerSec > autotune.bytes_per_sec) {
    autotune.bytes_per_sec = bytesPerSec;
    autotune.bytes_per_usec = bytesPerSec / 1000000.0f;

    log_notice(LD_GENERAL, "autotune: new max write speed is %f bytes/sec and %f bytes/usec",
        autotune.bytes_per_sec, autotune.bytes_per_usec);
  }

  log_info(LD_GENERAL,
      "autotune: global total="U64_FORMAT" kernel_would_flush="U64_FORMAT" limit="U64_FORMAT,
      ((long long unsigned int)autotune.now.total),
      ((long long unsigned int)autotune.now.kernel_would_flush),
      ((long long unsigned int)autotune.global_limit));
}

static size_t global_autotune_write_to_kernel(or_connection_t* orc, int* has_error) {
  /* make sure libevent will tell us when this one is available again */
  if(!connection_is_writing(TO_CONN(orc))) {
    connection_start_writing(TO_CONN(orc));
  }

  if (get_options()->AutotuneWriteUSec == 0) {
    return write_to_connection(TO_CONN(orc), 0, has_error);
  }

  size_t totalBytesWritten = 0;
  size_t bytesWritten = 1;
  while(bytesWritten > 0) {
    size_t limit = MIN(orc->autotune.remaining, autotune.global_limit);
    bytesWritten = limit>0 ? write_to_connection(TO_CONN(orc), limit, has_error) : 0;

    if (bytesWritten > 0) {
      totalBytesWritten += bytesWritten;
      orc->autotune.written_to_kernel += bytesWritten;
      autotune.now.written_to_kernel += bytesWritten;
      orc->autotune.remaining -= orc->autotune.remaining < bytesWritten ? orc->autotune.remaining : bytesWritten;
      autotune.global_limit -= autotune.global_limit < bytesWritten ? autotune.global_limit : bytesWritten;
    }
  }

  log_info(LD_GENERAL, "autotune: after write="U64_FORMAT" conn=%i outbuf_len="U64_FORMAT" remaining="U64_FORMAT" global limit="U64_FORMAT,
      ((long long unsigned int)totalBytesWritten),
      (int)TO_CONN(orc)->s,
      (has_error && !(*has_error)) ? (long long unsigned int)connection_get_outbuf_len(TO_CONN(orc)) : (long long unsigned int)0,
      ((long long unsigned int)orc->autotune.remaining),
      ((long long unsigned int)autotune.global_limit));

  return totalBytesWritten;
}

static void make_sure_write_event_exists() {
  if (!global_write_event_is_pending) {
    unsigned int usec = (unsigned int) get_options()->GlobalSchedulerUSec;
    global_write_event_is_pending = global_write_timer_create(usec);
  }
}

static smartlist_t* global_autotune_flush_orconn_outbufs(smartlist_t* pending_orconns) {
  /* flush as many bytes from the orconn outbufs as possible. return
   * list of orconns for which we should schedule more bytes. */
  smartlist_t* eligible = smartlist_new();
  size_t totalBytes = 0;

  while (smartlist_len(pending_orconns) > 0) {
    /* get the connection */
    or_connection_t* orc = smartlist_get(pending_orconns, 0);
    smartlist_remove(pending_orconns, orc);
    if(orc->base_.magic != OR_CONNECTION_MAGIC) {
      /* connection was freed */
      // TODO we should do this before its destroyed
      continue;
    }

    /* we are processing this conn now */
    orc->globalSchedulePending = 0;

    /* check conn buffer and cell queue status */
    unsigned int num_active_circs = circuitmux_num_active_circuits(TLS_CHAN_TO_BASE(orc->chan)->cmux);
    size_t conn_buf_len = connection_get_outbuf_len(TO_CONN(orc));

    log_info(LD_GENERAL, "global scheduler: socket %i has "U64_FORMAT
        " bytes in the conn out buf and %u active circuits",
        (int)TO_CONN(orc)->s,
        (long long unsigned int)conn_buf_len, num_active_circs);

    size_t bytesWritten = 0;
    int has_error = 0;
    if(conn_buf_len > 0) {
      /* try to write previously blocked bytes */
      bytesWritten = global_autotune_write_to_kernel(orc, &has_error);
      totalBytes += bytesWritten > 0 ? bytesWritten : 0;
    } else if(conn_buf_len == 0 && num_active_circs == 0) {
      /* sometimes 'writable' means we finished 'connecting', we need
       * to call this to complete the connection transition */
      write_to_connection(TO_CONN(orc), 0, &has_error);
    }

    if(has_error) {
      continue;
    }

    /* should we schedule more cells to this orconn this round? */
    if(get_options()->AutotuneWriteUSec) {
      /* autotuning - we can schedule more to outbuf if autotuning lets us */
      if(num_active_circs > 0) {
        /* we have more cells waiting in circ queue */
        if(orc->autotune.remaining > 0 && autotune.global_limit > 0) {
          /* schedule them this round */
          smartlist_add(eligible, orc);
        } else {
          /* schedule them next round */
          global_autotune_conn_write_callback(orc);
        }
      }
    } else {
      /* regular global scheduling - schedule at most 16 KiB to outbuf */
      if(num_active_circs > 0) {
        /* we have more cells waiting in circ queue */
        if((conn_buf_len + bytesWritten) < 16384) {
          /* schedule them this round */
          smartlist_add(eligible, orc);
        } else {
          /* schedule them next round */
          global_autotune_conn_write_callback(orc);
        }
      }
    }
  }

  /* if we ran out of tokens, dont schedule more */
  if(get_options()->AutotuneWriteUSec && autotune.global_limit == 0) {
    while(smartlist_len(eligible) > 0) {
      or_connection_t* orc = smartlist_get(eligible, 0);
      smartlist_remove(eligible, orc);
      if(circuitmux_num_active_circuits(TLS_CHAN_TO_BASE(orc->chan)->cmux) > 0) {
        /* schedule them next round */
        global_autotune_conn_write_callback(orc);
      }
    }
  }

  log_info(LD_GENERAL,
      "global scheduler: flushed "U64_FORMAT" previously scheduled bytes to kernel",
      ((long long unsigned int)(totalBytes)));

  return eligible;
}

static void global_autotune_schedule_orconns(smartlist_t* eligible_orconns) {
  /* choose cells from circuits in the eligible orconns and write them to the
   * orconn outbufs. return the orconns that got new bytes written. */
  size_t totalOutbufBytes = 0;
  size_t totalKernelBytes = 0;

  or_connection_t* chosen_orconn = NULL;
  channel_tls_t* chosen_chan = NULL;

  while (smartlist_len(eligible_orconns) > 0) {
    /* use scheduler to choose a circuit and its or_connection */
    chosen_chan = circuitmux_choose_channel(eligible_orconns);
    /* if no more orconns from our list have cells */
    if (!chosen_chan)
      break;

    chosen_orconn = TLS_CHAN_TO_ORCONN(chosen_chan);

    /* move some cells from that circuit to our tor socket buffer */
    unsigned int old_num_active_circs = circuitmux_num_active_circuits(TLS_CHAN_TO_BASE(chosen_chan)->cmux);
    size_t oldlen = connection_get_outbuf_len(TO_CONN(chosen_orconn));

    channel_flush_from_first_active_circuit(TLS_CHAN_TO_BASE(chosen_chan), 1);

    unsigned int new_num_active_circs = circuitmux_num_active_circuits(TLS_CHAN_TO_BASE(chosen_chan)->cmux);
    size_t newlen = connection_get_outbuf_len(TO_CONN(chosen_orconn));
    /* estimate the TLS header length that will also get written to the kernel later */
    //newlen += (size_t)74;

    /* how much did we schedule */
    size_t outputBytes = newlen > oldlen ? newlen - oldlen : 0;
    totalOutbufBytes += outputBytes;

    if(outputBytes > 0) {
      log_info(LD_GENERAL, "global scheduler: scheduled "U64_FORMAT" bytes "
            "to orconn=%i outbuf_len="U64_FORMAT" active circuits before=%u after=%u",
            (long long unsigned int)outputBytes, TO_CONN(chosen_orconn)->s,
            (long long unsigned int)newlen,
            old_num_active_circs, new_num_active_circs);
    }

    int has_error = 0;

    if(get_options()->AutotuneWriteUSec) {
      if(outputBytes == 0 || newlen >= chosen_orconn->autotune.remaining || newlen >= autotune.global_limit) {
        /* we will reach our write limit when we write these cells, lets stop scheduling more */
        smartlist_remove(eligible_orconns, chosen_orconn);

        /* flush the new bytes to the orconn outbuf */
        size_t bytesWritten = global_autotune_write_to_kernel(chosen_orconn, &has_error);
        totalKernelBytes += bytesWritten > 0 ? bytesWritten : 0;

        if(has_error) {
          continue;
        }

        /* if we STILL have more bytes, or we have more cells, try again next round */
        size_t blocked_len = connection_get_outbuf_len(TO_CONN(chosen_orconn));
        if(blocked_len > 0 || new_num_active_circs > 0) {
          global_autotune_conn_write_callback(chosen_orconn);
        }
      }
    } else {
      if(outputBytes == 0 || newlen >= 16384) {
        /* flush the new bytes to the orconn outbuf */
        size_t bytesWritten = global_autotune_write_to_kernel(chosen_orconn, &has_error);
        totalKernelBytes += bytesWritten > 0 ? bytesWritten : 0;

        if(has_error) {
          smartlist_remove(eligible_orconns, chosen_orconn);
          continue;
        }

        /* keep scheduling unless we STILL have too many bytes */
        size_t blocked_len = connection_get_outbuf_len(TO_CONN(chosen_orconn));
        if(outputBytes == 0 || blocked_len > 16384) {
          /* stop scheduling so we dont fill the orconn outbuf too much */
          smartlist_remove(eligible_orconns, chosen_orconn);

          /* if we still have active circuits with more cells, try next round */
          if(new_num_active_circs > 0) {
            global_autotune_conn_write_callback(chosen_orconn);
          }
        }
      }
    }
  }

  /* the orconns that are still eligible may have data to send to
   * kernel and may have more cells for next round */
  while (smartlist_len(eligible_orconns) > 0) {
    or_connection_t* orc = smartlist_get(eligible_orconns, 0);
    smartlist_remove(eligible_orconns, orc);

    int has_error = 0;
    size_t bytesWritten = global_autotune_write_to_kernel(chosen_orconn, &has_error);
    totalKernelBytes += bytesWritten > 0 ? bytesWritten : 0;

    if(has_error) {
      continue;
    }

    size_t blocked_len = connection_get_outbuf_len(TO_CONN(chosen_orconn));
    unsigned int num_active_circs = circuitmux_num_active_circuits(TLS_CHAN_TO_BASE(chosen_orconn->chan)->cmux);
    if(num_active_circs > 0 || blocked_len > 0) {
      global_autotune_conn_write_callback(orc);
    }
  }

  log_info(LD_GENERAL, "global scheduler: scheduled "U64_FORMAT" bytes "
      "to orconn outbufs and wrote "U64_FORMAT" bytes to kernel",
      (long long unsigned int)totalOutbufBytes, (long long unsigned int)totalKernelBytes);
}

/* libevent callback signature */
void global_conn_write_callback(evutil_socket_t fd, short events,
    void *args) {
  /* there is no longer a global write event scheduled */
  global_write_event_is_pending = 0;
  if (global_write_event) {
    tor_event_free(global_write_event);
    global_write_event = NULL;
  }

  tor_assert(pending_write_connection_lst);
  int n_pending = smartlist_len(pending_write_connection_lst);
  log_info(LD_GENERAL, "global scheduler: activated with %d pending orconns", n_pending);
  if(n_pending <= 0) {
    return;
  }

  /* some pending conns may have flushable bytes that we already
   * scheduled but got blocked on the kernel and are not currently be active
   * (meaning we can send data but don't currently have more cells we want
   * want to write to the outbuf). other conns have data in the outbuf to
   * write and are also willing to move more cells to the outbuf.
   */

  /****************************************
   * if autotuning, gather our connection stats and compute write limits
   ****************************************/

  if (get_options()->AutotuneWriteUSec) {
    global_autotune_preupdate();
    smartlist_t* all_conns = get_connection_array();
    SMARTLIST_FOREACH(all_conns, connection_t *, conn, {
      if(conn && connection_speaks_cells(conn)) {
        global_autotune_conn_update(TO_OR_CONN(conn));
      }
    });
    global_autotune_postupdate();
    if(autotune.global_limit == 0) {
      make_sure_write_event_exists();
      return;
    }
  }

  /* reset the pending list so we dont modify it while processing it */
  smartlist_t* pending = pending_write_connection_lst;
  pending_write_connection_lst = NULL;

  /****************************************
   * write all the outbuf data that we previously
   * scheduled but was blocked on the kernel
   ****************************************/

  smartlist_t* eligible_to_schedule = global_autotune_flush_orconn_outbufs(pending);
  tor_assert(smartlist_len(pending) == 0);
  smartlist_free(pending);

  /****************************************
   * schedule new cells to the tor orconn outbufs
   * and flush what we can to the kernel
   ****************************************/

  global_autotune_schedule_orconns(eligible_to_schedule);
  tor_assert(smartlist_len(eligible_to_schedule) == 0);
  smartlist_free(eligible_to_schedule);

//  if (get_options()->AutotuneWriteUSec) {
//    /* dynamically adjust the callback time to just before we expect the kernel to be empty */
//    double new_kernel_total = ((double)(autotune.now.total + autotune.now.written_to_kernel));
//    unsigned int new_interval_usec = ((unsigned int)(new_kernel_total / autotune.bytes_per_usec));
//    if(new_interval_usec < 1) {
//      new_interval_usec = 1;
//    }
//
//    /* reset the wait time interval */
//    get_options_mutable()->GlobalSchedulerUSec = new_interval_usec;
//  }
}

/* shadow intercepts this function to ensure the timer is handled properly
 * so dont change the signature */
int global_write_timer_create(unsigned int usec) {
  if (!global_write_event) {
    struct timeval tv;

    global_write_event = tor_evtimer_new(tor_libevent_get_base(),
        global_conn_write_callback, NULL );
    tv.tv_sec = 0;
    tv.tv_usec = usec;

    if (evtimer_add(global_write_event, &tv) < 0) {
      log_warn(LD_BUG, "Couldn't add timer for global write event");
      return 0; // the event will not be pending
    }
  }
  return 1; // there is an event pending
}

void global_write_refill_callback(evutil_socket_t fd, short events, void *args) {
  double refill_usec = (double)get_options()->AutotuneRefillUSec;
  double refill_tokens = refill_usec * autotune.bytes_per_usec;

  autotune.global_tokens += refill_tokens;

  /* if we've collected more than 1 byte worth of tokens, update limit */
  if(autotune.global_tokens >= 16384.0f) {
    size_t new_tokens = (size_t)autotune.global_tokens;
    autotune.global_limit += new_tokens;
    autotune.global_tokens -= (double)new_tokens;
  }

  /* make sure we dont overflow the bucket capacity */
  double limit_usec = (double)get_options()->AutotuneFillLimitUSec;
  double ceiling = MAX(limit_usec * autotune.bytes_per_usec, 32768.0f);

  if(((double)autotune.global_limit) > ceiling) {
    autotune.global_limit = (size_t)ceiling;
  }

  /* schedule another */
  if (autotune.global_write_refill_event) {
    tor_event_free(autotune.global_write_refill_event);
    autotune.global_write_refill_event = NULL;
  }
  global_write_refill_timer_create(get_options()->AutotuneRefillUSec);
}

int global_write_refill_timer_create(unsigned int usec) {
  if (!autotune.global_write_refill_event) {
    struct timeval tv;

    autotune.global_write_refill_event = tor_evtimer_new(tor_libevent_get_base(),
        global_write_refill_callback, NULL );
    tv.tv_sec = 0;
    tv.tv_usec = usec;

    if (evtimer_add(autotune.global_write_refill_event, &tv) < 0) {
      log_warn(LD_BUG, "Couldn't add timer for autotune write refill event");
      return 0; // the event will not be pending
    }
  }
  return 1; // there is an event pending
}

void global_autotune_conn_write_callback(or_connection_t* orc) {
  if(!autotune_initialized) {
    memset(&autotune, 0, sizeof(autotune_t));
    unsigned int awu = get_options()->AutotuneWriteUSec;
    if(awu > 0) {
      get_options_mutable()->GlobalSchedulerUSec = awu;
      if(!get_options()->AutotuneRefillUSec) {
        get_options_mutable()->AutotuneRefillUSec = awu;
      }
      if(!get_options()->AutotuneFillLimitUSec) {
        get_options_mutable()->AutotuneFillLimitUSec = awu;
      }
      tor_assert(global_write_refill_timer_create(get_options()->AutotuneRefillUSec));
	  log_notice(LD_GENERAL, "autotune: initialized AutotuneWriteUSec=%u AutotuneRefillUSec=%u AutotuneFillLimitUSec=%u",
				 awu, get_options()->AutotuneRefillUSec, get_options()->AutotuneFillLimitUSec);
    }
    autotune_initialized = 1;
    log_notice(LD_GENERAL, "global scheduler: initialized GlobalSchedulerUSec=%u", get_options()->GlobalSchedulerUSec);
  }

  /* only add it to the list if its not already there */
  if (!orc->globalSchedulePending) {
    if (!pending_write_connection_lst) {
      pending_write_connection_lst = smartlist_new();
    }
    smartlist_add(pending_write_connection_lst, orc);
    orc->globalSchedulePending = 1;
  }

  make_sure_write_event_exists();

  connection_stop_writing(TO_CONN(orc));
}

void global_autotune_remove_pending(or_connection_t* orc) {
  if(orc && pending_write_connection_lst && orc->globalSchedulePending) {
    smartlist_remove(pending_write_connection_lst, orc);
  }
}

void global_autotune_free() {
  if(pending_write_connection_lst) {
    smartlist_free(pending_write_connection_lst);
    pending_write_connection_lst = NULL;
  }
  if (global_write_event) {
    tor_event_free(global_write_event);
    global_write_event = NULL;
  }
  if (autotune.global_write_refill_event) {
    tor_event_free(autotune.global_write_refill_event);
    autotune.global_write_refill_event = NULL;
  }
}
