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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <xhyve/support/atomic.h>
#include <xhyve/xhyve.h>
#include <xhyve/block_if.h>
#include <xhyve/vdsk/vdsk.h>
#include <xhyve/vdsk/vdsk-int.h>
#include <xhyve/vdsk/vdsk-vdi.h>

// XXX vvv GPL (snarfed from qemu)
typedef struct {
    char text[0x40];
    uint32_t signature;
    uint32_t version;
    uint32_t header_size;
    uint32_t image_type;
    uint32_t image_flags;
    char description[256];
    uint32_t offset_bmap;
    uint32_t offset_data;
    uint32_t cylinders;         /* disk geometry, unused here */
    uint32_t heads;             /* disk geometry, unused here */
    uint32_t sectors;           /* disk geometry, unused here */
    uint32_t sector_size;
    uint32_t unused1;
    uint64_t disk_size;
    uint32_t block_size;
    uint32_t block_extra;       /* unused here */
    uint32_t blocks_in_image;
    uint32_t blocks_allocated;
    uuid_t uuid_image;
    uuid_t uuid_last_snap;
    uuid_t uuid_link;
    uuid_t uuid_parent;
    uint64_t unused2[7];
} VdiHeader;
// XXX ^^^ GPL (snarfed from qemu)

struct vdsk_vdi_ctx {
	struct vdsk super;
	int bc_fd;
	int delay;
	int dirty;
	int blog2;
	uint32_t *bmap;
	VdiHeader vdi;
};

/* xhyve: FIXME
 *
 * As VDIs probably need multiple reads and writes we can not
 * use preadv/pwritev, we need to serialize reads and writes
 * for the time being until we find a better solution.
 */

static int
getlog2(uint32_t n)
{
	int x;
	if (!n || !powerof2(n)) {
		return -1;
	}
	for (x = 0; n >>= 1; x++) {
	}
	return x;
}

static int
is_zero(char *block, size_t size)
{
#if 1
	const size_t width = sizeof(long);
	while (size && (uintptr_t)block % width) {
		if (*block) {
			return 0;
		}
		size--;
		block++;
	}
	while (size >= width) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
		if (*(long *)block) {
			return 0;
		}
#pragma clang diagnostic pop
		size -= width;
		block += width;
	}
#endif
	while (size) {
		if (*block) {
			return 0;
		}
		size--;
		block++;
	}
	return 1;
}

static int
update_header(struct vdsk_vdi_ctx *vp, size_t first, size_t last)
{
	size_t p0;
	size_t p1;
	ssize_t n;
	if (!vp->dirty) {
		return 0;
	}
	p0 = first * sizeof(uint32_t) & ~((size_t)DEV_BSIZE - 1);
	p1 = (last * sizeof(uint32_t) + DEV_BSIZE - 1) & ~((size_t)DEV_BSIZE - 1);
	n = pwrite(vp->bc_fd, (char *)vp->bmap + p0, p1 - p0, (off_t)p0 + vp->vdi.offset_bmap);
	if (n < 0) {
		// XXX corrupted
		return errno;
	}
	n = pwrite(vp->bc_fd, &vp->vdi, sizeof(VdiHeader), 0);
	if (n < 0) {
		// XXX corrupted
		return errno;
	}
	vp->dirty = 0;
	return 0;
}

static ssize_t
vdi_pread(struct vdsk_vdi_ctx *vp, void *buf, size_t nbyte, off_t offset)
{
	char *dst = buf;
	ssize_t n;
	size_t chunk;
	uint32_t offset_of_block;
	size_t block_size = vp->vdi.block_size;
	size_t block_num = (size_t)(offset >> vp->blog2);
	size_t offset_in = (size_t)offset & (block_size - 1);
	int growable = (vp->vdi.image_type == 1);

	while (nbyte) {
		chunk = block_size - offset_in;
		if (chunk > nbyte) {
			chunk = nbyte;
		}
		offset_of_block = vp->bmap[block_num];
		if (offset_of_block >= 0xfffffffe && growable) {
			memset(dst, 0, chunk);
		} else {
			n = pread(vp->bc_fd, dst, chunk, (off_t)vp->vdi.offset_data + ((off_t)offset_of_block << vp->blog2) + (off_t)offset_in);
			if (n < 0) {
				goto err;
			}
		}
		nbyte -= chunk;
		dst += chunk;
		block_num++;
		offset_in = 0;
	}

	return dst - (char *)buf;
err:
	return -1;
}

static ssize_t
vdi_pwrite(struct vdsk_vdi_ctx *vp, void *buf, size_t nbyte, off_t offset)
{
	char *dst = buf;
	ssize_t n;
	size_t chunk;
	uint32_t offset_of_block;
	size_t block_size = vp->vdi.block_size;
	size_t block_num = (size_t)(offset >> vp->blog2);
	size_t offset_in = (size_t)offset & (block_size - 1);
	int growable = (vp->vdi.image_type == 1);
	size_t first = 0, last = 0;
	char *block = NULL;

	while (nbyte) {
		chunk = block_size - offset_in;
		if (chunk > nbyte) {
			chunk = nbyte;
		}
		offset_of_block = vp->bmap[block_num];
		if (offset_of_block >= 0xfffffffe && growable) {
			if (block == NULL) {
				block = malloc(block_size);
				if (block == NULL) {
					break;
				}
				first = block_num;
			}
			last = block_num;
			memset(block, 0, offset_in);
			memcpy(block + offset_in, dst, chunk);
			memset(block + offset_in + chunk, 0, block_size - offset_in - chunk);
			if (is_zero(block, block_size)) {
				vp->bmap[block_num] = 0xfffffffe;
				vp->dirty |= (offset_of_block != 0xfffffffe);
			} else {
				if (vp->vdi.blocks_allocated == vp->vdi.blocks_in_image) {
					goto err;
				}
				offset_of_block = vp->vdi.blocks_allocated++;
				vp->bmap[block_num] = offset_of_block;
				vp->dirty |= 1;
				n = pwrite(vp->bc_fd, block, block_size, (off_t)vp->vdi.offset_data + ((off_t)offset_of_block << vp->blog2));
				if (n < 0) {
					goto err;
				}
			}
		} else {
			n = pwrite(vp->bc_fd, dst, chunk, (off_t)vp->vdi.offset_data + ((off_t)offset_of_block << vp->blog2) + (off_t)offset_in);
			if (n < 0) {
				goto err;
			}
		}
		nbyte -= chunk;
		dst += chunk;
		block_num++;
		offset_in = 0;
	}

	if (!vp->delay) {
		int rv = update_header(vp, first, last + 1);
		if (rv < 0) {
			goto err;
		}
	}

	free(block);
	return dst - (char *)buf;
err:
	free(block);
	return -1;
}

static ssize_t
preadv(struct vdsk_vdi_ctx *vp, const struct iovec *iov, int iovcnt, off_t offset)
{
	int i;
	ssize_t len, total = 0;

	for (i = 0; i < iovcnt; i++) {
		len = vdi_pread(vp, iov[i].iov_base, iov[i].iov_len, offset);
		if (len < 0) {
			return len;
		}
		total += len;
		offset += iov[i].iov_len;
	}

	return total;
}

static ssize_t
pwritev(struct vdsk_vdi_ctx *vp, const struct iovec *iov, int iovcnt, off_t offset)
{
	int i;
	ssize_t len, total = 0;

	for (i = 0; i < iovcnt; i++) {
		len = vdi_pwrite(vp, iov[i].iov_base, iov[i].iov_len, offset);
		if (len < 0) {
			return len;
		}
		total += len;
		offset += iov[i].iov_len;
	}

	return total;
}

static int
disk_close(struct vdsk *vdsk)
{
	struct vdsk_vdi_ctx *vp = (struct vdsk_vdi_ctx *)vdsk;

	if (vp->delay) {
		update_header(vp, 0, vp->vdi.blocks_in_image);
	}
	free(vp->bmap);
	close(vp->bc_fd);
	free(vp);

	return (0);
}

static int
disk_read(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf)
{
	struct vdsk_vdi_ctx *vp = (struct vdsk_vdi_ctx *)vdsk;

	ssize_t clen, len, off, boff, voff;
	int i, err;

	err = 0;

	if (buf == NULL) {
		if ((len = preadv(vp, br->br_iov, br->br_iovcnt,
			   br->br_offset)) < 0)
			err = errno;
		else
			br->br_resid -= len;
		return err;
	}
	i = 0;
	off = voff = 0;
	while (br->br_resid > 0) {
		len = MIN(br->br_resid, MAXPHYS);
		if (vdi_pread(vp, buf, ((size_t) len), br->br_offset + off) < 0)
		{
			err = errno;
			break;
		}
		boff = 0;
		do {
			clen = MIN((len - boff),
				(((ssize_t) br->br_iov[i].iov_len) - voff));
			memcpy(((void *) (((uintptr_t) br->br_iov[i].iov_base) +
				((size_t) voff))), buf + boff, clen);
			if (clen < (((ssize_t) br->br_iov[i].iov_len) - voff))
				voff += clen;
			else {
				i++;
				voff = 0;
			}
			boff += clen;
		} while (boff < len);
		off += len;
		br->br_resid -= len;
	}

	return err;
}

static int
disk_write(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf)
{
	struct vdsk_vdi_ctx *vp = (struct vdsk_vdi_ctx *)vdsk;

	ssize_t clen, len, off, boff, voff;
	int i, err;

	err = 0;

	if (vdsk->bc_rdonly) {
		err = EROFS;
		return err;
	}
	if (buf == NULL) {
		if ((len = pwritev(vp, br->br_iov, br->br_iovcnt,
			    br->br_offset)) < 0)
			err = errno;
		else
			br->br_resid -= len;
		return err;
	}
	i = 0;
	off = voff = 0;
	while (br->br_resid > 0) {
		len = MIN(br->br_resid, MAXPHYS);
		boff = 0;
		do {
			clen = MIN((len - boff),
				(((ssize_t) br->br_iov[i].iov_len) - voff));
			memcpy((buf + boff),
				((void *) (((uintptr_t) br->br_iov[i].iov_base) +
					((size_t) voff))), clen);
			if (clen < (((ssize_t) br->br_iov[i].iov_len) - voff))
				voff += clen;
			else {
				i++;
				voff = 0;
			}
			boff += clen;
		} while (boff < len);
		if (vdi_pwrite(vp, buf, ((size_t) len), br->br_offset +
		    off) < 0) {
			err = errno;
			break;
		}
		off += len;
		br->br_resid -= len;
	}

	return err;
}

static int
disk_flush(struct vdsk *vdsk)
{
	struct vdsk_vdi_ctx *vp = (struct vdsk_vdi_ctx *)vdsk;

	int err = 0;

	if (vp->delay) {
		err = update_header(vp, 0, vp->vdi.blocks_in_image);
	}
	if (fsync(vp->bc_fd))
		err = errno;

	return err;
}

static int
disk_delete(struct vdsk *vdsk, UNUSED struct blockif_req *br)
{
	int err = 0;

	if (vdsk->bc_rdonly) {
		err = EROFS;
	} else {
		err = EOPNOTSUPP;
	}

	return err;
}

struct vdsk *
vdsk_vdi_open(const char *optstr, int numthr, int *fatal)
{
	char *nopt, *xopts, *cp;
	struct vdsk_vdi_ctx *bc;
	struct stat sbuf;
	off_t psectsz;
	int extra, fd;
	int ro, delay;
	int block_shift;
	VdiHeader header;
	uint32_t *bmap;
	size_t sz, bmap_size;

	assert(numthr == 1);

	*fatal = 1;
	fd = -1;
	ro = 0;
	delay = 0;

	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
	nopt = xopts = strdup(optstr);
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* file or device pathname */
			continue;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else if (!strcmp(cp, "delay"))
			delay = 1;
		else {
			fprintf(stderr, "Invalid device option \"%s\"\n", cp);
			goto err;
		}
	}

	extra = 0;

	fd = open(nopt, (ro ? O_RDONLY : O_RDWR) | extra);
	if (fd < 0 && !ro) {
		/* Attempt a r/w fail with a r/o open */
		fd = open(nopt, O_RDONLY | extra);
		ro = 1;
	}

	if (fd < 0) {
		perror("Could not open backing file");
		goto err;
	}

	if (fstat(fd, &sbuf) < 0) {
		perror("Could not stat backing file");
		goto err;
	}
	psectsz = sbuf.st_blksize;

	sz = (size_t)read(fd, &header, sizeof(header));
	if (sz != sizeof(header)) {
		perror("Could not read backing file");
		goto err;
	}
	if (header.signature != 0xBEDA107F) {
		*fatal = 0;
		goto err;
	}
	if (header.version != 0x00010001) {
		goto err;
	}
	if (header.sector_size != DEV_BSIZE ||
		header.offset_bmap % DEV_BSIZE ||
		header.offset_data % DEV_BSIZE ||
		header.block_size % header.sector_size ||
		(block_shift = getlog2(header.block_size)) < 0) {
		fprintf(stderr, "Invalid VDI\n");
		goto err;
	}
	if (header.blocks_allocated > header.blocks_in_image) {
		fprintf(stderr, "Invalid VDI\n");
		goto err;
	}
	if (header.image_type != 1 && header.image_type != 2) {
		fprintf(stderr, "Invalid VDI\n");
		goto err;
	}
	if (header.image_type == 1 && header.image_flags & 2) {
		fprintf(stderr, "Invalid VDI\n");
		goto err;
	}
	if (header.image_type == 2 && header.blocks_allocated != header.blocks_in_image) {
		fprintf(stderr, "Invalid VDI\n");
		goto err;
	}

	bmap_size = (header.blocks_in_image * sizeof(uint32_t) + DEV_BSIZE - 1) & ~((size_t)DEV_BSIZE - 1);

	bmap = malloc(bmap_size);
	if (!bmap) {
		perror("malloc");
		goto err;
	}

	sz = (size_t)pread(fd, bmap, bmap_size, header.offset_bmap);
	if (sz != bmap_size) {
		perror("bmap");
		goto err2;
	}

	bc = calloc(1, sizeof(struct vdsk_vdi_ctx));
	if (bc == NULL) {
		perror("calloc");
		goto err2;
	}

	bc->bc_fd = fd;
	bc->delay = (short)delay;
	bc->dirty = 0;
	bc->blog2 = block_shift;
	bc->bmap = bmap;
	memcpy(&bc->vdi, &header, sizeof(header));
	bc->super.bc_isgeom = 0;
	bc->super.bc_candelete = 0;
	bc->super.bc_rdonly = ro;
	bc->super.bc_size = (off_t)header.disk_size;
	bc->super.bc_sectsz = DEV_BSIZE;
	bc->super.bc_psectsz = (int) psectsz;
	bc->super.bc_psectoff = 0;

	bc->super.close = disk_close;
	bc->super.read = disk_read;
	bc->super.write = disk_write;
	bc->super.flush = disk_flush;
	bc->super.delete = disk_delete;

	free(nopt);
	return (struct vdsk *)bc;
err2:
	free(bmap);
err:
	if (fd >= 0)
		close(fd);
	free(nopt);
	return (NULL);
}
