/*-
 * Copyright (c) 2016 Daniel Borca
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
 *
 * $FreeBSD$
 */

#pragma once

#include <xhyve/support/atomic.h>
#include <xhyve/xhyve.h>
#include <xhyve/block_if.h>

struct vdsk;

struct vdsk *vdsk_open(const char *optstr, int numthr);

int vdsk_close(struct vdsk *vdsk);
int vdsk_read(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf);
int vdsk_write(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf);
int vdsk_flush(struct vdsk *vdsk);
int vdsk_delete(struct vdsk *vdsk, struct blockif_req *br);

void vdsk_chs(const struct vdsk *vdsk, uint16_t *c, uint8_t *h, uint8_t *s);

off_t vdsk_size(const struct vdsk *vdsk);
int vdsk_sectsz(const struct vdsk *vdsk);
void vdsk_psectsz(const struct vdsk *vdsk, int *size, int *off);
int vdsk_is_ro(const struct vdsk *vdsk);
int vdsk_candelete(const struct vdsk *vdsk);

uint8_t *vdsk_physbuf(const struct vdsk *vdsk);
