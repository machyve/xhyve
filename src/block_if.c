/*-
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
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
#include <xhyve/mevent.h>
#include <xhyve/block_if.h>

#define BLOCKIF_SIG 0xb109b109
/* xhyve: FIXME
 *
 * // #define BLOCKIF_NUMTHR 8
 *
 * As split disk images probably need multiple reads and writes we can not
 * use preadv/pwritev, we need to serialize reads and writes
 * for the time being until we find a better solution.
 */
#define BLOCKIF_NUMTHR 1

#define BLOCKIF_MAXREQ (64 + BLOCKIF_NUMTHR)

enum blockop {
	BOP_READ,
	BOP_WRITE,
	BOP_FLUSH,
	BOP_DELETE
};

enum blockstat {
	BST_FREE,
	BST_BLOCK,
	BST_PEND,
	BST_BUSY,
	BST_DONE
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
struct blockif_elem {
	TAILQ_ENTRY(blockif_elem) be_link;
	struct blockif_req *be_req;
	enum blockop be_op;
	enum blockstat be_status;
	pthread_t be_tid;
	off_t be_block;
};

struct blockif_ctxt {
	int bc_magic;

	int *bc_fd;
	int bc_num_fd;

	int bc_ischr;
	int bc_isgeom;
	int bc_candelete;
	int bc_rdonly;
	size_t bc_size;
	size_t bc_split;
	int bc_sectsz;
	int bc_psectsz;
	int bc_psectoff;
	int bc_closing;
	pthread_t bc_btid[BLOCKIF_NUMTHR];
	pthread_mutex_t bc_mtx;
	pthread_cond_t bc_cond;
	/* Request elements and free/pending/busy queues */
	TAILQ_HEAD(, blockif_elem) bc_freeq;
	TAILQ_HEAD(, blockif_elem) bc_pendq;
	TAILQ_HEAD(, blockif_elem) bc_busyq;
	struct blockif_elem	bc_reqs[BLOCKIF_MAXREQ];
};

static pthread_once_t blockif_once = PTHREAD_ONCE_INIT;

struct blockif_sig_elem {
	pthread_mutex_t bse_mtx;
	pthread_cond_t bse_cond;
	int bse_pending;
	struct blockif_sig_elem *bse_next;
};

static struct blockif_sig_elem *blockif_bse_head;

#pragma clang diagnostic pop

static int
blockif_enqueue(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	struct blockif_elem *be, *tbe;
	off_t off;
	int i;

	be = TAILQ_FIRST(&bc->bc_freeq);
	assert(be != NULL);
	assert(be->be_status == BST_FREE);
	TAILQ_REMOVE(&bc->bc_freeq, be, be_link);
	be->be_req = breq;
	be->be_op = op;
	switch (op) {
	case BOP_READ:
	case BOP_WRITE:
	case BOP_DELETE:
		off = breq->br_offset;
		for (i = 0; i < breq->br_iovcnt; i++)
			off += breq->br_iov[i].iov_len;
		break;
	case BOP_FLUSH:
		off = OFF_MAX;
	}
	be->be_block = off;
	TAILQ_FOREACH(tbe, &bc->bc_pendq, be_link) {
		if (tbe->be_block == breq->br_offset)
			break;
	}
	if (tbe == NULL) {
		TAILQ_FOREACH(tbe, &bc->bc_busyq, be_link) {
			if (tbe->be_block == breq->br_offset)
				break;
		}
	}
	if (tbe == NULL)
		be->be_status = BST_PEND;
	else
		be->be_status = BST_BLOCK;
	TAILQ_INSERT_TAIL(&bc->bc_pendq, be, be_link);
	return (be->be_status == BST_PEND);
}

static int
blockif_dequeue(struct blockif_ctxt *bc, pthread_t t, struct blockif_elem **bep)
{
	struct blockif_elem *be;

	TAILQ_FOREACH(be, &bc->bc_pendq, be_link) {
		if (be->be_status == BST_PEND)
			break;
		assert(be->be_status == BST_BLOCK);
	}
	if (be == NULL)
		return (0);
	TAILQ_REMOVE(&bc->bc_pendq, be, be_link);
	be->be_status = BST_BUSY;
	be->be_tid = t;
	TAILQ_INSERT_TAIL(&bc->bc_busyq, be, be_link);
	*bep = be;
	return (1);
}

static void
blockif_complete(struct blockif_ctxt *bc, struct blockif_elem *be)
{
	struct blockif_elem *tbe;

	if (be->be_status == BST_DONE || be->be_status == BST_BUSY)
		TAILQ_REMOVE(&bc->bc_busyq, be, be_link);
	else
		TAILQ_REMOVE(&bc->bc_pendq, be, be_link);
	TAILQ_FOREACH(tbe, &bc->bc_pendq, be_link) {
		if (tbe->be_req->br_offset == be->be_block)
			tbe->be_status = BST_PEND;
	}
	be->be_tid = 0;
	be->be_status = BST_FREE;
	be->be_req = NULL;
	TAILQ_INSERT_TAIL(&bc->bc_freeq, be, be_link);
}

static int
blockif_get_fd(struct blockif_ctxt *bc, size_t offset) {
	if (bc->bc_split) {
		int i = (int)(offset / bc->bc_split);
		return bc->bc_fd[i];
	} else {
		return bc->bc_fd[0];
	}
}

static ssize_t
blockif_read_data(struct blockif_ctxt *bc, uint8_t *buf, size_t len, size_t offset) {
	// find correct fd
	int fd = blockif_get_fd(bc, offset);
	ssize_t bytes = 0;

	if (bc->bc_split) {
		lseek(fd, (off_t)(offset % bc->bc_split), SEEK_SET);
	} else {
		lseek(fd, (off_t)offset, SEEK_SET);
	}

	// is this a multi part read
	if ((bc->bc_split) && (offset % bc->bc_split + len > bc->bc_split)) {
		// read is longer than current segment

		// read until end of segment
		size_t len1 = bc->bc_split - (offset % bc->bc_split);
		bytes = read(fd, buf, len1);
		if (bytes < 0) {
			return bytes;
		}

		// get next fd and read the rest
		size_t len2 = len - len1;
		fd = blockif_get_fd(bc, offset + len1);
		lseek(fd, 0, SEEK_SET);
		ssize_t result = read(fd, buf + len1, len2);
		if (result < 0) {
			return result;
		}
		bytes += result;
	} else {
		// read does not cross segment border
		bytes = read(fd, buf, len);
	}

	// return read bytes
	return bytes;
}

static ssize_t
blockif_write_data(struct blockif_ctxt *bc, uint8_t *buf, size_t len, size_t offset) {
	// find correct fd
	int fd = blockif_get_fd(bc, offset);
	ssize_t bytes = 0;

	if (bc->bc_split) {
		lseek(fd, (off_t)(offset % bc->bc_split), SEEK_SET);
	} else {
		lseek(fd, (off_t)offset, SEEK_SET);
	}

	// is this a multi part write
	if ((bc->bc_split) && (offset % bc->bc_split + len > bc->bc_split)) {
		// write is longer than current segment

		// write until end of segment
		size_t len1 = bc->bc_split - (offset % bc->bc_split);
		bytes = write(fd, buf, len1);
		if (bytes < 0) {
			return bytes;
		}

		// get next fd and write the rest
		size_t len2 = len - len1;
		fd = blockif_get_fd(bc, offset + len1);
		lseek(fd, 0, SEEK_SET);
		ssize_t result = write(fd, buf + len1, len2);
		if (result < 0) {
			return result;
		}
		bytes += result;
	} else {
		// write does not cross segment border
		bytes = write(fd, buf, len);
	}

	// return written bytes
	return bytes;
}

static void
blockif_proc(struct blockif_ctxt *bc, struct blockif_elem *be, uint8_t *buf)
{
	struct blockif_req *br;
	// off_t arg[2];
	ssize_t clen, len, off, boff, voff;
	int i, err;

	br = be->be_req;
	if (br->br_iovcnt <= 1)
		buf = NULL;
	err = 0;
	switch (be->be_op) {
	case BOP_READ:
		if (buf == NULL) {
			// as we have to account for split disk images we disassemble
			// the iovec buffers and call read for each of them
			size_t offset = (size_t)br->br_offset;
			for(i = 0; i < br->br_iovcnt; i++) {
				len = blockif_read_data(bc, br->br_iov[i].iov_base, br->br_iov[i].iov_len, offset);
				if (len < 0) {
					err = errno;
				} else {
					br->br_resid -= len;
				}
				offset += br->br_iov[i].iov_len;
			}
			break;
		}
		i = 0;
		off = voff = 0;
		while (br->br_resid > 0) {
			len = MIN(br->br_resid, MAXPHYS);

			if (blockif_read_data(bc, buf, (size_t)len, (size_t)(br->br_offset + off)) < 0) {
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
		break;
	case BOP_WRITE:
		if (bc->bc_rdonly) {
			err = EROFS;
			break;
		}
		if (buf == NULL) {
			// as we have to account for split disk images we disassemble
			// the iovec buffers and call write for each of them
			size_t offset = (size_t)br->br_offset;
			for(i = 0; i < br->br_iovcnt; i++) {
				len = blockif_write_data(bc, br->br_iov[i].iov_base, br->br_iov[i].iov_len, offset);
				if (len < 0) {
					err = errno;
				} else {
					br->br_resid -= len;
				}
				offset += br->br_iov[i].iov_len;
			}
			break;
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

			if (blockif_write_data(bc, buf, (size_t)len, (size_t)(br->br_offset + off)) < 0) {
				err = errno;
				break;
			}
			off += len;
			br->br_resid -= len;
		}
		break;
	case BOP_FLUSH:
		for(i = 0; i < bc->bc_num_fd; i++) {
			if (bc->bc_ischr) {
				if (ioctl(bc->bc_fd[i], DKIOCSYNCHRONIZECACHE))
					err = errno;
			} else if (fsync(bc->bc_fd[i]))
				err = errno;
		}
		break;
	case BOP_DELETE:
		if (!bc->bc_candelete) {
			err = EOPNOTSUPP;
		// } else if (bc->bc_rdonly) {
		// 	err = EROFS;
		// } else if (bc->bc_ischr) {
		// 	arg[0] = br->br_offset;
		// 	arg[1] = br->br_resid;
		// 	if (ioctl(bc->bc_fd, DIOCGDELETE, arg)) {
		// 		err = errno;
		// 	} else {
		// 		br->br_resid = 0;
		// 	}
		} else {
			err = EOPNOTSUPP;
		}
		break;
	}

	be->be_status = BST_DONE;

	(*br->br_callback)(br, err);
}

static void *
blockif_thr(void *arg)
{
	struct blockif_ctxt *bc;
	struct blockif_elem *be;
	pthread_t t;
	uint8_t *buf;

	bc = arg;
	if (bc->bc_isgeom)
		buf = malloc(MAXPHYS);
	else
		buf = NULL;
	t = pthread_self();

	pthread_mutex_lock(&bc->bc_mtx);
	for (;;) {
		while (blockif_dequeue(bc, t, &be)) {
			pthread_mutex_unlock(&bc->bc_mtx);
			blockif_proc(bc, be, buf);
			pthread_mutex_lock(&bc->bc_mtx);
			blockif_complete(bc, be);
		}
		/* Check ctxt status here to see if exit requested */
		if (bc->bc_closing)
			break;
		pthread_cond_wait(&bc->bc_cond, &bc->bc_mtx);
	}
	pthread_mutex_unlock(&bc->bc_mtx);

	if (buf)
		free(buf);
	pthread_exit(NULL);
	return (NULL);
}

static void
blockif_sigcont_handler(UNUSED int signal, UNUSED enum ev_type type,
	UNUSED void *arg)
{
	struct blockif_sig_elem *bse;

	for (;;) {
		/*
		 * Process the entire list even if not intended for
		 * this thread.
		 */
		do {
			bse = blockif_bse_head;
			if (bse == NULL)
				return;
		} while (!atomic_cmpset_ptr((uintptr_t *)&blockif_bse_head,
					    (uintptr_t)bse,
					    (uintptr_t)bse->bse_next));

		pthread_mutex_lock(&bse->bse_mtx);
		bse->bse_pending = 0;
		pthread_cond_signal(&bse->bse_cond);
		pthread_mutex_unlock(&bse->bse_mtx);
	}
}

static void
blockif_init(void)
{
	mevent_add(SIGCONT, EVF_SIGNAL, blockif_sigcont_handler, NULL);
	(void) signal(SIGCONT, SIG_IGN);
}

struct blockif_ctxt *
blockif_open(const char *optstr, UNUSED const char *ident)
{
	// char name[MAXPATHLEN];
	char *nopt, *xopts, *cp, tmp[255];
	struct blockif_ctxt *bc;
	struct stat sbuf;
	// struct diocgattr_arg arg;
	size_t size, psectsz, psectoff, split;
	int extra, fd, sectsz;
	int nocache, sync, ro, candelete, geom, ssopt, pssopt;
	int *fds;

	pthread_once(&blockif_once, blockif_init);

	fd = -1;
	fds = NULL;
	ssopt = 0;
	nocache = 0;
	sync = 0;
	ro = 0;
	size = 0;
	split = 0;

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
		else if (sscanf(cp, "size=%s", tmp) == 1) {
			uint64_t num = 0;
			if (expand_number(tmp, &num)) {
				fprintf(stderr, "xhyve: could not parse size parameter: %s", strerror(errno));
				goto err;
			}
			size = (size_t)num;
		}
		else if (sscanf(cp, "split=%s", tmp) == 1) { /* split into chunks */
			uint64_t num = 0;
			if (expand_number(tmp, &num)) {
				fprintf(stderr, "xhyve: could not parse split parameter: %s", strerror(errno));
				goto err;
			}
			split = (size_t)num;
		}
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

	if (split != 0) {
		// open multiple files
		if (size == 0) {
			perror("xhyve: when using 'split' a 'size' is required!");
			goto err;
		}

		size_t num_parts = size / split;
		fds = malloc(sizeof(int) * num_parts);
		for (size_t i = 0; i < num_parts; i++) {
			fds[i] = -1;
		}

		printf("Split disk, opening %zu image parts\n", num_parts);

		for (size_t i = 0; i < num_parts; i++) {
			size_t len = strlen(nopt) + 6;
			char *filename = calloc(len, 1);
			snprintf(filename, len, "%s.%04zu", nopt, i);

			printf(" - %s\n", filename);

			fd = open(filename, (ro ? O_RDONLY : O_RDWR | O_CREAT) | extra);
			if (fd < 0 && !ro) {
				perror("Could not open backing file r/w, reverting to readonly");
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

			if (sbuf.st_size == 0) {
				// create image file
				printf("   -> file does not exist, creating empty file\n");
				fchmod(fd, 0660);
				char buffer[1024];
				memset(buffer, 0, 1024);
				for(size_t j = 0; j < split / 1024; j++) {
					write(fd, buffer, 1024);
				}
				lseek(fd, 0, SEEK_SET);
			}

			fds[i] = fd;
			free(filename);
		}
	} else {
        // open a single file

        printf("Single image disk\n");

		fd = open(nopt, (ro ? O_RDONLY : O_RDWR | O_CREAT) | extra);
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

		if (size == 0) {
			size = (size_t)sbuf.st_size;
		}
		if (sbuf.st_size == 0) {
			// TODO: make growing disks possible
			// create image file
			printf(" -> file does not exist, creating empty file\n");
			fchmod(fd, 0660);
			char buffer[1024];
			memset(buffer, 0, 1024);
			for(size_t i = 0; i < size / 1024; i++) {
				write(fd, buffer, 1024);
			}
			lseek(fd, 0, SEEK_SET);
		}
	}

    /*
	 * Deal with raw devices
	 */
	sectsz = DEV_BSIZE;
	psectsz = psectoff = 0;
	candelete = geom = 0;
	if (S_ISCHR(sbuf.st_mode)) {
		perror("xhyve: raw device support unimplemented");
		goto err;
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
		psectsz = (size_t)sbuf.st_blksize;

	if (ssopt != 0) {
		if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
		    ssopt > pssopt) {
			fprintf(stderr, "Invalid sector size %d/%d\n",
			    ssopt, pssopt);
			goto err;
		}

		// /*
		//  * Some backend drivers (e.g. cd0, ada0) require that the I/O
		//  * size be a multiple of the device's sector size.
		//  *
		//  * Validate that the emulated sector size complies with this
		//  * requirement.
		//  */
		// if (S_ISCHR(sbuf.st_mode)) {
		// 	if (ssopt < sectsz || (ssopt % sectsz) != 0) {
		// 		fprintf(stderr, "Sector size %d incompatible "
		// 		    "with underlying device sector size %d\n",
		// 		    ssopt, sectsz);
		// 		goto err;
		// 	}
		// }

		sectsz = ssopt;
		psectsz = (size_t)pssopt;
		psectoff = 0;
	}

	bc = calloc(1, sizeof(struct blockif_ctxt));
	if (bc == NULL) {
		perror("calloc");
		goto err;
	}

	bc->bc_magic = (int) BLOCKIF_SIG;
	if (split == 0) {
		bc->bc_num_fd = 1;
		bc->bc_fd = malloc(sizeof(int));
		bc->bc_fd[0] = fd;
	} else {
		bc->bc_num_fd = (int)(size / split);
		bc->bc_fd = fds;
	}
	bc->bc_ischr = S_ISCHR(sbuf.st_mode);
	bc->bc_isgeom = geom;
	bc->bc_candelete = candelete;
	bc->bc_rdonly = ro;
	bc->bc_size = size;
	bc->bc_split = split;
	bc->bc_sectsz = sectsz;
	bc->bc_psectsz = (int) psectsz;
	bc->bc_psectoff = (int) psectoff;
	pthread_mutex_init(&bc->bc_mtx, NULL);
	pthread_cond_init(&bc->bc_cond, NULL);
	TAILQ_INIT(&bc->bc_freeq);
	TAILQ_INIT(&bc->bc_pendq);
	TAILQ_INIT(&bc->bc_busyq);
	for (int i = 0; i < BLOCKIF_MAXREQ; i++) {
		bc->bc_reqs[i].be_status = BST_FREE;
		TAILQ_INSERT_HEAD(&bc->bc_freeq, &bc->bc_reqs[i], be_link);
	}

	for (int i = 0; i < BLOCKIF_NUMTHR; i++) {
		pthread_create(&bc->bc_btid[i], NULL, blockif_thr, bc);
	}

	return (bc);
err:
	if (fd >= 0)
		close(fd);
	if (fds != NULL) {
		int num_fds = (int)(size / split);
		for (int i = 0; i < num_fds; i++) {
			if (fds[i] >= 0) {
				close(fds[i]);
			}
		}
		free(fds);
	}
	return (NULL);
}

static int
blockif_request(struct blockif_ctxt *bc, struct blockif_req *breq,
		enum blockop op)
{
	int err;

	err = 0;

	pthread_mutex_lock(&bc->bc_mtx);
	if (!TAILQ_EMPTY(&bc->bc_freeq)) {
		/*
		 * Enqueue and inform the block i/o thread
		 * that there is work available
		 */
		if (blockif_enqueue(bc, breq, op))
			pthread_cond_signal(&bc->bc_cond);
	} else {
		/*
		 * Callers are not allowed to enqueue more than
		 * the specified blockif queue limit. Return an
		 * error to indicate that the queue length has been
		 * exceeded.
		 */
		err = E2BIG;
	}
	pthread_mutex_unlock(&bc->bc_mtx);

	return (err);
}

int
blockif_read(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (blockif_request(bc, breq, BOP_READ));
}

int
blockif_write(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (blockif_request(bc, breq, BOP_WRITE));
}

int
blockif_flush(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (blockif_request(bc, breq, BOP_FLUSH));
}

int
blockif_delete(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (blockif_request(bc, breq, BOP_DELETE));
}

int
blockif_cancel(struct blockif_ctxt *bc, struct blockif_req *breq)
{
	struct blockif_elem *be;

	assert(bc->bc_magic == ((int) BLOCKIF_SIG));

	pthread_mutex_lock(&bc->bc_mtx);
	/*
	 * Check pending requests.
	 */
	TAILQ_FOREACH(be, &bc->bc_pendq, be_link) {
		if (be->be_req == breq)
			break;
	}
	if (be != NULL) {
		/*
		 * Found it.
		 */
		blockif_complete(bc, be);
		pthread_mutex_unlock(&bc->bc_mtx);

		return (0);
	}

	/*
	 * Check in-flight requests.
	 */
	TAILQ_FOREACH(be, &bc->bc_busyq, be_link) {
		if (be->be_req == breq)
			break;
	}
	if (be == NULL) {
		/*
		 * Didn't find it.
		 */
		pthread_mutex_unlock(&bc->bc_mtx);
		return (EINVAL);
	}

	/*
	 * Interrupt the processing thread to force it return
	 * prematurely via it's normal callback path.
	 */
	while (be->be_status == BST_BUSY) {
		struct blockif_sig_elem bse, *old_head;

		pthread_mutex_init(&bse.bse_mtx, NULL);
		pthread_cond_init(&bse.bse_cond, NULL);

		bse.bse_pending = 1;

		do {
			old_head = blockif_bse_head;
			bse.bse_next = old_head;
		} while (!atomic_cmpset_ptr((uintptr_t *)&blockif_bse_head,
					    (uintptr_t)old_head,
					    (uintptr_t)&bse));

		pthread_kill(be->be_tid, SIGCONT);

		pthread_mutex_lock(&bse.bse_mtx);
		while (bse.bse_pending)
			pthread_cond_wait(&bse.bse_cond, &bse.bse_mtx);
		pthread_mutex_unlock(&bse.bse_mtx);
	}

	pthread_mutex_unlock(&bc->bc_mtx);

	/*
	 * The processing thread has been interrupted.  Since it's not
	 * clear if the callback has been invoked yet, return EBUSY.
	 */
	return (EBUSY);
}

int
blockif_close(struct blockif_ctxt *bc)
{
	void *jval;
	int err, i;

	err = 0;

	assert(bc->bc_magic == ((int) BLOCKIF_SIG));

	/*
	 * Stop the block i/o thread
	 */
	pthread_mutex_lock(&bc->bc_mtx);
	bc->bc_closing = 1;
	pthread_mutex_unlock(&bc->bc_mtx);
	pthread_cond_broadcast(&bc->bc_cond);
	for (i = 0; i < BLOCKIF_NUMTHR; i++) {
		pthread_join(bc->bc_btid[i], &jval);
	}

	/* XXX Cancel queued i/o's ??? */

	/*
	 * Release resources
	 */
	bc->bc_magic = 0;
	for(i = 0; i < bc->bc_num_fd; i++) {
		close(bc->bc_fd[i]);
	}
	free(bc->bc_fd);
	free(bc);

	return (0);
}

/*
 * Return virtual C/H/S values for a given block. Use the algorithm
 * outlined in the VHD specification to calculate values.
 */
void
blockif_chs(struct blockif_ctxt *bc, uint16_t *c, uint8_t *h, uint8_t *s)
{
	off_t sectors;		/* total sectors of the block dev */
	off_t hcyl;		/* cylinders times heads */
	uint16_t secpt;		/* sectors per track */
	uint8_t heads;

	assert(bc->bc_magic == ((int) BLOCKIF_SIG));

	sectors = (off_t)(bc->bc_size / (size_t)bc->bc_sectsz);

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
blockif_size(struct blockif_ctxt *bc)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (off_t)(bc->bc_size);
}

int
blockif_sectsz(struct blockif_ctxt *bc)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (bc->bc_sectsz);
}

void
blockif_psectsz(struct blockif_ctxt *bc, int *size, int *off)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	*size = bc->bc_psectsz;
	*off = bc->bc_psectoff;
}

int
blockif_queuesz(struct blockif_ctxt *bc)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (BLOCKIF_MAXREQ - 1);
}

int
blockif_is_ro(struct blockif_ctxt *bc)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (bc->bc_rdonly);
}

int
blockif_candelete(struct blockif_ctxt *bc)
{
	assert(bc->bc_magic == ((int) BLOCKIF_SIG));
	return (bc->bc_candelete);
}
