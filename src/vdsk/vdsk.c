/*-
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
 * Copyright (c) 2015 xhyve developers
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

#include <sys/param.h>

#include <xhyve/support/atomic.h>
#include <xhyve/xhyve.h>
#include <xhyve/block_if.h>
#include <xhyve/vdsk/vdsk.h>
#include <xhyve/vdsk/vdsk-int.h>
#include <xhyve/vdsk/vdsk-raw.h>

struct vdsk *
vdsk_open(const char *optstr, int numthr)
{
	/* for now, the one and only backend */
	return vdsk_raw_open(optstr, numthr);
}

int
vdsk_close(struct vdsk *vdsk)
{
	return vdsk->close(vdsk);
}

int
vdsk_read(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf)
{
	return vdsk->read(vdsk, br, buf);
}

int
vdsk_write(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf)
{
	return vdsk->write(vdsk, br, buf);
}

int
vdsk_flush(struct vdsk *vdsk)
{
	return vdsk->flush(vdsk);
}

int
vdsk_delete(struct vdsk *vdsk, struct blockif_req *br)
{
	return vdsk->delete(vdsk, br);
}

uint8_t *
vdsk_physbuf(const struct vdsk *vdsk)
{
	if (vdsk->bc_isgeom) {
		return malloc(MAXPHYS);
	}
	return NULL;
}

/*
 * Return virtual C/H/S values for a given block. Use the algorithm
 * outlined in the VHD specification to calculate values.
 */
void
vdsk_chs(const struct vdsk *vdsk, uint16_t *c, uint8_t *h, uint8_t *s)
{
	off_t sectors;		/* total sectors of the block dev */
	off_t hcyl;		/* cylinders times heads */
	uint16_t secpt;		/* sectors per track */
	uint8_t heads;

	sectors = vdsk->bc_size / vdsk->bc_sectsz;

	/* Clamp the size to the largest possible with CHS */
	if (sectors > 65535LL*16*255)
		sectors = 65535LL*16*255;

	if (sectors >= 65536LL*16*63) {
		secpt = 255;
		heads = 16;
		hcyl = sectors / secpt;
	} else {
		secpt = 17;
		hcyl = sectors / secpt;
		heads = (uint8_t) ((hcyl + 1023) / 1024);

		if (heads < 4)
			heads = 4;

		if (hcyl >= (heads * 1024) || heads > 16) {
			secpt = 31;
			heads = 16;
			hcyl = sectors / secpt;
		}
		if (hcyl >= (heads * 1024)) {
			secpt = 63;
			heads = 16;
			hcyl = sectors / secpt;
		}
	}

	*c = (uint16_t) (hcyl / heads);
	*h = heads;
	*s = (uint8_t) secpt;
}

/*
 * Accessors
 */

off_t
vdsk_size(const struct vdsk *vdsk)
{
	return (vdsk->bc_size);
}

int
vdsk_sectsz(const struct vdsk *vdsk)
{
	return (vdsk->bc_sectsz);
}

void
vdsk_psectsz(const struct vdsk *vdsk, int *size, int *off)
{
	*size = vdsk->bc_psectsz;
	*off = vdsk->bc_psectoff;
}

int
vdsk_is_ro(const struct vdsk *vdsk)
{
	return (vdsk->bc_rdonly);
}

int
vdsk_candelete(const struct vdsk *vdsk)
{
	return (vdsk->bc_candelete);
}
