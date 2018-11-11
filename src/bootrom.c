/*-
 * Copyright (c) 2015 Neel Natu <neel@freebsd.org>
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

#include <sys/param.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <xhyve/support/misc.h>

#include <xhyve/vmm/vmm.h>
#include <xhyve/vmm/vmm_api.h>
#include <xhyve/bootrom.h>

#define	MAX_BOOTROM_SIZE	(16 * 1024 * 1024)	/* 16 MB */

int
bootrom_init(const char *romfile)
{
	struct stat sbuf;
	ssize_t rlen;
	char *ptr;
	int fd, i, rv;

	rv = -1;
	fd = open(romfile, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening bootrom \"%s\": %s\n",
		    romfile, strerror(errno));
		goto done;
	}

        if (fstat(fd, &sbuf) < 0) {
		fprintf(stderr, "Could not fstat bootrom file \"%s\": %s\n",
		    romfile, strerror(errno));
		goto done;
        }

	/*
	 * Limit bootrom size to 16MB so it doesn't encroach into reserved
	 * MMIO space (e.g. APIC, HPET, MSI).
	 */
	if (sbuf.st_size > MAX_BOOTROM_SIZE || sbuf.st_size < XHYVE_PAGE_SIZE) {
		fprintf(stderr, "Invalid bootrom size %lld\n", sbuf.st_size);
		goto done;
	}

	if (sbuf.st_size & XHYVE_PAGE_MASK) {
		fprintf(stderr, "Bootrom size %lld is not a multiple of the "
		    "page size\n", sbuf.st_size);
		goto done;
	}

	/* Map the bootrom into the guest address space */
	if (xh_setup_bootrom_memory((size_t)sbuf.st_size, (void **)&ptr) != 0)
    {
        fprintf(stderr, "hv_setup_bootrom_memory failed\n");
		goto done;
    }

	/* Read 'romfile' into the guest address space */
	for (i = 0; i < sbuf.st_size / XHYVE_PAGE_SIZE; i++) {
		rlen = read(fd, ptr + i * XHYVE_PAGE_SIZE, XHYVE_PAGE_SIZE);
		if (rlen != XHYVE_PAGE_SIZE) {
			fprintf(stderr, "Incomplete read of page %d of bootrom "
			    "file %s: %ld bytes\n", i, romfile, rlen);
			goto done;
		}
	}
	rv = 0;
done:
	if (fd >= 0)
		close(fd);
	return (rv);
}
