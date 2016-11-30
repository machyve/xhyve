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
#include <xhyve/vdsk/vdsk-raw.h>

struct vdsk_raw_ctx {
	struct vdsk super;
	int bc_fd;
	int bc_ischr;
};

/* xhyve: FIXME
 *
 * OS X does not support preadv/pwritev, we need to serialize reads and writes
 * for the time being until we find a better solution.
 */

static ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	off_t res;

	res = lseek(fd, offset, SEEK_SET);
	assert(res == offset);
	return readv(fd, iov, iovcnt);
}

static ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	off_t res;

	res = lseek(fd, offset, SEEK_SET);
	assert(res == offset);
	return writev(fd, iov, iovcnt);
}

static int
disk_close(struct vdsk *vdsk)
{
	struct vdsk_raw_ctx *vp = (struct vdsk_raw_ctx *)vdsk;

	close(vp->bc_fd);
	free(vp);

	return (0);
}

static int
disk_read(struct vdsk *vdsk, struct blockif_req *br, uint8_t *buf)
{
	const struct vdsk_raw_ctx *vp = (const struct vdsk_raw_ctx *)vdsk;

	ssize_t clen, len, off, boff, voff;
	int i, err;

	err = 0;

	if (buf == NULL) {
		if ((len = preadv(vp->bc_fd, br->br_iov, br->br_iovcnt,
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
		if (pread(vp->bc_fd, buf, ((size_t) len), br->br_offset + off) < 0)
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
	const struct vdsk_raw_ctx *vp = (const struct vdsk_raw_ctx *)vdsk;

	ssize_t clen, len, off, boff, voff;
	int i, err;

	err = 0;

	if (vdsk->bc_rdonly) {
		err = EROFS;
		return err;
	}
	if (buf == NULL) {
		if ((len = pwritev(vp->bc_fd, br->br_iov, br->br_iovcnt,
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
		if (pwrite(vp->bc_fd, buf, ((size_t) len), br->br_offset +
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
	const struct vdsk_raw_ctx *vp = (const struct vdsk_raw_ctx *)vdsk;

	int err = 0;

	if (vp->bc_ischr) {
		if (ioctl(vp->bc_fd, DKIOCSYNCHRONIZECACHE))
			err = errno;
	} else if (fsync(vp->bc_fd))
		err = errno;

	return err;
}

static int
disk_delete(struct vdsk *vdsk, UNUSED struct blockif_req *br)
{
	// const struct vdsk_raw_ctx *vp = (const struct vdsk_raw_ctx *)vdsk;

	// off_t arg[2];
	int err = 0;

	if (!vdsk->bc_candelete) {
		err = EOPNOTSUPP;
	// } else if (vdsk->bc_rdonly) {
	// 	err = EROFS;
	// } else if (vp->bc_ischr) {
	// 	arg[0] = br->br_offset;
	// 	arg[1] = br->br_resid;
	// 	if (ioctl(vp->bc_fd, DIOCGDELETE, arg)) {
	// 		err = errno;
	// 	} else {
	// 		br->br_resid = 0;
	// 	}
	} else {
		err = EOPNOTSUPP;
	}

	return err;
}

struct vdsk *
vdsk_raw_open(const char *optstr, int numthr, int *fatal)
{
	// char name[MAXPATHLEN];
	char *nopt, *xopts, *cp;
	struct vdsk_raw_ctx *bc;
	struct stat sbuf;
	// struct diocgattr_arg arg;
	off_t size, psectsz, psectoff, blocks;
	int extra, fd, sectsz;
	int nocache, sync, ro, candelete, geom, ssopt, pssopt;

	assert(numthr == 1);

	*fatal = 1;
	fd = -1;
	ssopt = 0;
	nocache = 0;
	sync = 0;
	ro = 0;

	pssopt = 0;
	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
	nopt = xopts = strdup(optstr);
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* file or device pathname */
			continue;
		else if (!strcmp(cp, "nocache"))
			nocache = 1;
		else if (!strcmp(cp, "sync") || !strcmp(cp, "direct"))
			sync = 1;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else if (sscanf(cp, "sectorsize=%d/%d", &ssopt, &pssopt) == 2)
			;
		else if (sscanf(cp, "sectorsize=%d", &ssopt) == 1)
			pssopt = ssopt;
		else {
			fprintf(stderr, "Invalid device option \"%s\"\n", cp);
			goto err;
		}
	}

	extra = 0;
	if (nocache) {
		perror("xhyve: nocache support unimplemented");
		goto err;
		// extra |= O_DIRECT;
	}
	if (sync)
		extra |= O_SYNC;

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

    /*
	 * Deal with raw devices
	 */
	size = sbuf.st_size;
	sectsz = DEV_BSIZE;
	psectsz = psectoff = 0;
	candelete = geom = 0;
	blocks = 0;
	if (S_ISCHR(sbuf.st_mode)) {
		if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blocks) < 0 ||
			ioctl(fd, DKIOCGETBLOCKSIZE, &sectsz) ||
			ioctl(fd, DKIOCGETPHYSICALBLOCKSIZE, &psectsz))
		{
			perror("Could not fetch dev blk/sector size");
			goto err;
		}
		size = blocks * sectsz;
		assert(size != 0);
		assert(psectsz != 0);
		// if (ioctl(fd, DIOCGMEDIASIZE, &size) < 0 ||
		// 	ioctl(fd, DIOCGSECTORSIZE, &sectsz))
		// {
		// 	perror("Could not fetch dev blk/sector size");
		// 	goto err;
		// }
		// assert(size != 0);
		// assert(sectsz != 0);
		// if (ioctl(fd, DIOCGSTRIPESIZE, &psectsz) == 0 && psectsz > 0)
		// 	ioctl(fd, DIOCGSTRIPEOFFSET, &psectoff);
		// strlcpy(arg.name, "GEOM::candelete", sizeof(arg.name));
		// arg.len = sizeof(arg.value.i);
		// if (ioctl(fd, DIOCGATTR, &arg) == 0)
		// 	candelete = arg.value.i;
		// if (ioctl(fd, DIOCGPROVIDERNAME, name) == 0)
		// 	geom = 1;
	} else
		psectsz = sbuf.st_blksize;

	if (ssopt != 0) {
		if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
		    ssopt > pssopt) {
			fprintf(stderr, "Invalid sector size %d/%d\n",
			    ssopt, pssopt);
			goto err;
		}

		/*
		 * Some backend drivers (e.g. cd0, ada0) require that the I/O
		 * size be a multiple of the device's sector size.
		 *
		 * Validate that the emulated sector size complies with this
		 * requirement.
		 */
		if (S_ISCHR(sbuf.st_mode)) {
			if (ssopt < sectsz || (ssopt % sectsz) != 0) {
				fprintf(stderr, "Sector size %d incompatible "
				    "with underlying device sector size %d\n",
				    ssopt, sectsz);
				goto err;
			}
		}

		sectsz = ssopt;
		psectsz = pssopt;
		psectoff = 0;
	}

	bc = calloc(1, sizeof(struct vdsk_raw_ctx));
	if (bc == NULL) {
		perror("calloc");
		goto err;
	}

	bc->bc_fd = fd;
	bc->bc_ischr = S_ISCHR(sbuf.st_mode);
	bc->super.bc_isgeom = geom;
	bc->super.bc_candelete = candelete;
	bc->super.bc_rdonly = ro;
	bc->super.bc_size = size;
	bc->super.bc_sectsz = sectsz;
	bc->super.bc_psectsz = (int) psectsz;
	bc->super.bc_psectoff = (int) psectoff;

	bc->super.close = disk_close;
	bc->super.read = disk_read;
	bc->super.write = disk_write;
	bc->super.flush = disk_flush;
	bc->super.delete = disk_delete;

	free(nopt);
	return (struct vdsk *)bc;
err:
	if (fd >= 0)
		close(fd);
	free(nopt);
	return (NULL);
}
