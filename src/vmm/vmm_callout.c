/*-
 * Copyright (c) 2015 xhyve developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>

#include <xhyve/support/misc.h>
#include <xhyve/vmm/vmm_callout.h>

static mach_timebase_info_data_t timebase_info;
static dispatch_queue_t queue;
static bool initialized = false;

static inline uint64_t nanos_to_abs(uint64_t nanos) {
  return (nanos * timebase_info.denom) / timebase_info.numer;
}

static inline uint64_t abs_to_nanos(uint64_t abs) {
  return (abs * timebase_info.numer) / timebase_info.denom;
}

static inline uint64_t sbt2mat(sbintime_t sbt) {
  uint64_t s, ns;
  
  s = (((uint64_t) sbt) >> 32);
  ns = (((uint64_t) 1000000000) * (uint32_t) sbt) >> 32;
  
  return (nanos_to_abs((s * 1000000000) + ns));
}

void binuptime(struct bintime *bt) {
  uint64_t ns;
  
  ns = abs_to_nanos(mach_absolute_time());

  bt->sec = (ns / 1000000000);
  bt->frac = (((ns % 1000000000) * (((uint64_t) 1 << 63) / 500000000)));
}

void getmicrotime(struct timeval *tv) {
  uint64_t ns, sns;

  ns = abs_to_nanos(mach_absolute_time());

  sns = (ns / 1000000000);
  tv->tv_sec = (long) sns;
  tv->tv_usec = (int) ((ns - sns) / 1000);
}

static void dispatcher(void* data) {
  struct callout *c = (struct callout *) data;

  if (!(c->flags & (CALLOUT_ACTIVE | CALLOUT_PENDING))) {
    abort();
  }

  /* dispatch */
  c->flags &= ~CALLOUT_PENDING;

  c->callout(c->argument);

  /* note: after the handler has been invoked the callout structure can look
   *       much differently, the handler may have rescheduled the callout or
   *       even freed it.
   *
   *       if the callout is still enqueued it means that it hasn't been
   *       freed by the user
   *
   *       reset || drain || !stop
   */

  if (c->queued) {
    /* if the callout hasn't been rescheduled, remove it */
    if (((c->flags & CALLOUT_PENDING) == 0) || (c->flags & CALLOUT_WAITING)) {
      c->flags |= CALLOUT_COMPLETED;
      dispatch_suspend(c->timer);
      c->queued = 0;
    }
  }
}

void callout_init(struct callout *c, int mpsafe) {
  if (!mpsafe) {
    abort();
  }

  memset(c, 0, sizeof(struct callout));

  c->timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
  dispatch_set_context(c->timer, c);
  dispatch_source_set_event_handler_f(c->timer, dispatcher);
}

int callout_stop_safe(struct callout *c, int drain) {
  int result = 0;

  if ((drain) && (callout_pending(c) || (callout_active(c) && !callout_completed(c)))) {
    if (c->flags & CALLOUT_WAITING) {
      abort();
    }

    /* wait for callout */
    c->flags |= CALLOUT_WAITING;

    while (!callout_completed(c)) {
      // FIXME
      //pthread_cond_wait(&c->wait, NULL);
    }

    c->flags &= ~CALLOUT_WAITING;
    result = 1;
  }

  if (c->queued) {
    dispatch_suspend(c->timer);
    c->queued = 0;
  }

  /* clear flags */
  c->flags &= ~(CALLOUT_ACTIVE | CALLOUT_PENDING | CALLOUT_COMPLETED | CALLOUT_WAITING);

  return result;
}

int callout_reset_sbt(struct callout *c, sbintime_t sbt,
  UNUSED sbintime_t precision, void (*ftn)(void *), void *arg, int flags) {
  int result;

  if (!((flags == 0) || (flags == C_ABSOLUTE)) || (c->flags != 0)) {
    /* FIXME */
    //printf("XHYVE: callout_reset_sbt 0x%08x 0x%08x\r\n", flags, c->flags);
    //abort();
  }

  c->timeout = sbt2mat(sbt);

  if (flags == C_ABSOLUTE) {
    c->timeout -= mach_absolute_time();
  }

  c->timeout = abs_to_nanos(c->timeout);

  result = callout_stop_safe(c, 0);

  c->callout = ftn;
  c->argument = arg;
  c->flags |= (CALLOUT_PENDING | CALLOUT_ACTIVE);

  dispatch_time_t start = dispatch_time(DISPATCH_TIME_NOW, (int64_t) c->timeout);
  dispatch_source_set_timer(c->timer, start, DISPATCH_TIME_FOREVER, 0);
  dispatch_resume(c->timer);
  c->queued = 1;

  return result;
}

void callout_system_init(void) {
  if (initialized) {
    return;
  }

  mach_timebase_info(&timebase_info);

  queue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);

  initialized = true;
}
