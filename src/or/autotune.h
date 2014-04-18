#ifndef AUTOTUNE_H_
#define AUTOTUNE_H_

#include "or.h"

#include <sys/ioctl.h>
#include <netinet/tcp.h>

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#undef IOCTL_INQ
#ifdef SIOCINQ
#define IOCTL_INQ SIOCINQ
#elif defined ( TIOCINQ )
#define IOCTL_INQ TIOCINQ
#elif defined ( FIONREAD )
#define IOCTL_INQ FIONREAD
#endif

#undef IOCTL_OUTQ
#ifdef SIOCOUTQ
#define IOCTL_OUTQ SIOCOUTQ
#elif defined ( TIOCOUTQ )
#define IOCTL_OUTQ TIOCOUTQ
#endif

typedef struct socket_stats_t {
  struct timeval ts;
  int refcount;
#ifdef TCP_INFO
  struct tcp_info tcpi;
#endif
  uint32_t inqlen;
  uint32_t outqlen;
  uint32_t sndbuflen;
  uint32_t rcvbuflen;
} socket_stats_t;

typedef struct autotune_ack_s autotune_ack_t;
struct autotune_ack_s {
  struct timespec t;
  u_int32_t n;
  int heap_index;
};

typedef struct autotune_bytes_s autotune_bytes_t;
struct autotune_bytes_s {
  struct timespec time;
  size_t total; // total bytes in kernel
  size_t kernel_would_flush; // total additional bytes kernel would flush if we wrote them
  size_t written_to_kernel; // number of bytes we wrote this round
};

typedef struct autotune_s autotune_t;
struct autotune_s {
  double bytes_per_sec;
  double bytes_per_usec;
  autotune_bytes_t last;
  autotune_bytes_t now;
  size_t global_limit;
  double global_tokens;
  struct event *global_write_refill_event;
};

void global_conn_write_callback(evutil_socket_t fd, short events, void *args);
void global_autotune_conn_write_callback(or_connection_t* orc);
void global_autotune_remove_pending(or_connection_t* orc);
void global_autotune_free();

/* shadow intercepts these functions so dont change the signatures */
int global_write_timer_create(unsigned int usec);
int global_write_refill_timer_create(unsigned int usec);
double global_autotune_get_write_speed();

#endif /* AUTOTUNE_H_ */
