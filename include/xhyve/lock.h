/*-
 * Copyright (c) 2016 xhyve developers
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <Availability.h>

#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED >= 101200 /* __MAC_10_12 */
	#include <os/lock.h>
	#define xhyve_lock_t os_unfair_lock
	#define XHYVE_LOCK_INIT(V, LOCK) (V)->LOCK = OS_UNFAIR_LOCK_INIT;
	#define XHYVE_LOCK(V, LOCK) os_unfair_lock_lock(&(V)->LOCK)
	#define XHYVE_UNLOCK(V, LOCK) os_unfair_lock_unlock(&(V)->LOCK)
#else
	#include <libkern/OSAtomic.h>
	#define xhyve_lock_t OSSpinLock
	#define XHYVE_LOCK_INIT(V, LOCK) (V)->LOCK = OS_SPINLOCK_INIT;
	#define XHYVE_LOCK(V, LOCK) OSSpinLockLock(&(V)->LOCK)
	#define XHYVE_UNLOCK(V, LOCK) OSSpinLockUnlock(&(V)->LOCK)
#endif
