/*-
 * Copyright (c) 2011 NetApp, Inc.
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
 *
 * $FreeBSD$
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <xhyve/support/misc.h>
#include <xhyve/support/atomic.h>
#include <xhyve/support/linker_set.h>
#include <xhyve/support/md5.h>
#include <xhyve/xhyve.h>
#include <xhyve/pci_emul.h>
#include <xhyve/mevent.h>
#include <xhyve/virtio.h>


#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <poll.h>
#include <pcap/pcap.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>


#define USE_MEVENT 0

#define VTNET_RINGSZ 1024
#define VTNET_MAXSEGS 32

/*
 * Host capabilities.  Note that we only offer a few of these.
 */
// #define VIRTIO_NET_F_CSUM (1 << 0) /* host handles partial cksum */
// #define VIRTIO_NET_F_GUEST_CSUM (1 << 1) /* guest handles partial cksum */
#define VIRTIO_NET_F_MAC (1 << 5) /* host supplies MAC */
// #define VIRTIO_NET_F_GSO_DEPREC (1 << 6) /* deprecated: host handles GSO */
// #define VIRTIO_NET_F_GUEST_TSO4 (1 << 7) /* guest can rcv TSOv4 */
// #define VIRTIO_NET_F_GUEST_TSO6 (1 << 8) /* guest can rcv TSOv6 */
// #define VIRTIO_NET_F_GUEST_ECN (1 << 9) /* guest can rcv TSO with ECN */
// #define VIRTIO_NET_F_GUEST_UFO (1 << 10) /* guest can rcv UFO */
// #define VIRTIO_NET_F_HOST_TSO4 (1 << 11) /* host can rcv TSOv4 */
// #define VIRTIO_NET_F_HOST_TSO6 (1 << 12) /* host can rcv TSOv6 */
// #define VIRTIO_NET_F_HOST_ECN (1 << 13) /* host can rcv TSO with ECN */
// #define VIRTIO_NET_F_HOST_UFO (1 << 14) /* host can rcv UFO */
#define VIRTIO_NET_F_MRG_RXBUF (1 << 15) /* host can merge RX buffers */
#define VIRTIO_NET_F_STATUS (1 << 16) /* config status field available */
// #define VIRTIO_NET_F_CTRL_VQ (1 << 17) /* control channel available */
// #define VIRTIO_NET_F_CTRL_RX (1 << 18) /* control channel RX mode support */
// #define VIRTIO_NET_F_CTRL_VLAN (1 << 19) /* control channel VLAN filtering */
// #define VIRTIO_NET_F_GUEST_ANNOUNCE (1 << 21) /* guest can send gratuit. pkts */

#define VTNET_S_HOSTCAPS \
	(VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | \
	VIRTIO_F_NOTIFY_ON_EMPTY)

#define ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpacked"

/*
 * PCI config-space "registers"
 */
struct virtio_net_config {
	uint8_t mac[6];
	uint16_t status;
} __packed;

/*
 * Queue definitions.
 */
#define VTNET_RXQ 0
#define VTNET_TXQ 1
// #define VTNET_CTLQ 2 /* NB: not yet supported */
#define VTNET_MAXQ 3

/*
 * Fixed network header size
 */
struct virtio_net_rxhdr {
	uint8_t vrh_flags;
	uint8_t vrh_gso_type;
	uint16_t vrh_hdr_len;
	uint16_t vrh_gso_size;
	uint16_t vrh_csum_start;
	uint16_t vrh_csum_offset;
	uint16_t vrh_bufs;
} __packed;

#pragma clang diagnostic pop

/*
 * Debug printf
 */
static int pci_vtnet_debug;
#define DPRINTF(params) if (pci_vtnet_debug) printf params
#define WPRINTF(params) printf params

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
/*
 * Per-device softc
 */
struct pci_vtnet_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_queues[VTNET_MAXQ - 1];
	pthread_mutex_t vsc_mtx;
	struct mevent *vsc_mevp;
	pcap_t *vsc_pcap;
	int vsc_pcapfd;
	int vsc_rx_ready;
	volatile int resetting;/* set and checked outside lock */
	uint64_t vsc_features; /* negotiated features */
	struct virtio_net_config vsc_config;
	pthread_mutex_t rx_mtx;
	int rx_in_progress;
	int rx_vhdrlen;
	int rx_merge; /* merged rx bufs in use */
	pthread_t tx_tid;
	pthread_mutex_t tx_mtx;
	pthread_cond_t tx_cond;
	int tx_in_progress;
};
#pragma clang diagnostic pop

static void pci_vtnet_reset(void *);
/* static void pci_vtnet_notify(void *, struct vqueue_info *); */
static int pci_vtnet_cfgread(void *, int, int, uint32_t *);
static int pci_vtnet_cfgwrite(void *, int, int, uint32_t);
static void pci_vtnet_neg_features(void *, uint64_t);

static struct virtio_consts vtnet_vi_consts = {
	"vtnet",		/* our name */
	VTNET_MAXQ - 1,		/* we currently support 2 virtqueues */
	sizeof(struct virtio_net_config), /* config reg size */
	pci_vtnet_reset,	/* reset */
	NULL,			/* device-wide qnotify -- not used */
	pci_vtnet_cfgread,	/* read PCI config */
	pci_vtnet_cfgwrite,	/* write PCI config */
	pci_vtnet_neg_features,	/* apply negotiated features */
	VTNET_S_HOSTCAPS,	/* our capabilities */
};

/*
 * If the transmit thread is active then stall until it is done.
 */
static void
pci_vtnet_txwait(struct pci_vtnet_softc *sc)
{

	pthread_mutex_lock(&sc->tx_mtx);
	while (sc->tx_in_progress) {
		pthread_mutex_unlock(&sc->tx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->tx_mtx);
	}
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * If the receive thread is active then stall until it is done.
 */
static void
pci_vtnet_rxwait(struct pci_vtnet_softc *sc)
{

	pthread_mutex_lock(&sc->rx_mtx);
	while (sc->rx_in_progress) {
		pthread_mutex_unlock(&sc->rx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->rx_mtx);
	}
	pthread_mutex_unlock(&sc->rx_mtx);
}

static void
pci_vtnet_reset(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device reset requested !\n"));

	sc->resetting = 1;

	/*
	 * Wait for the transmit and receive threads to finish their
	 * processing.
	 */
	pci_vtnet_txwait(sc);
	pci_vtnet_rxwait(sc);

	sc->vsc_rx_ready = 0;
	sc->rx_merge = 1;
	sc->rx_vhdrlen = sizeof(struct virtio_net_rxhdr);

	/* now reset rings, MSI-X vectors, and negotiated capabilities */
	vi_reset_dev(&sc->vsc_vs);

	sc->resetting = 0;
}


#define PCAP_INTF_MAX_MTU 10000
static char out_buf[PCAP_INTF_MAX_MTU];

/*
 * Called to send a buffer chain out to the device via PCAP 
 */
static void
pci_vtnet_pcap_tx(struct pci_vtnet_softc *sc, struct iovec *iov, int iovcnt,
		 int len)
{
	static char pad[60]; /* all zero bytes */

	if (sc->vsc_pcap == NULL)
		return;

	/*
	 * If the length is < 60, pad out to that and add the
	 * extra zero'd segment to the iov. It is guaranteed that
	 * there is always an extra iov available by the caller.
	 */
	if (len < 60) {
		iov[iovcnt].iov_base = pad;
		iov[iovcnt].iov_len = (size_t) (60 - len);
		iovcnt++;
	}
	/*
	 * Populate the temporary buffer from IOVs and then inject it.
	 * If there is only one IOV, then there is a useless copy made.
	 */
	int iov_idx = 0;
	size_t out_idx = 0;
	while((iov_idx < iovcnt) && (out_idx + iov[iov_idx].iov_len < sizeof(out_buf)) ) {
		memcpy(&out_buf[out_idx], iov[iov_idx].iov_base, iov[iov_idx].iov_len);
		out_idx += iov[iov_idx].iov_len;
		iov_idx++;
        }
        pcap_inject(sc->vsc_pcap, out_buf, out_idx);

}

/*
 *  Called when there is read activity on the PCAP file descriptor.
 * Each buffer posted by the guest is assumed to be able to contain
 * an entire ethernet frame + rx header.
 */

static __inline struct iovec *
rx_iov_trim(struct iovec *iov, int *niov, int tlen)
{
	struct iovec *riov;

	/* XXX short-cut: assume first segment is >= tlen */
	assert(iov[0].iov_len >= ((size_t) tlen));

	iov[0].iov_len -= ((size_t) tlen);
	if (iov[0].iov_len == 0) {
		assert(*niov > 1);
		*niov -= 1;
		riov = &iov[1];
	} else {
		iov[0].iov_base = (void *)((uintptr_t)iov[0].iov_base +
			((size_t) tlen));
		riov = &iov[0];
	}

	return (riov);
}

static void
pci_vtnet_pcap_rx(struct pci_vtnet_softc *sc)
{
	struct iovec iov[VTNET_MAXSEGS], *riov;
	struct vqueue_info *vq;
	void *vrx;
	int len, n;
	uint16_t idx;
	struct pcap_pkthdr ph;

	/*
	 * Should never be called without a valid pcap
	 */
	assert(sc->vsc_pcap != NULL);
	assert(sc->vsc_pcapfd != -1);

	/*
	 * But, will be called when the rx ring hasn't yet
	 * been set up or the guest is resetting the device.
	 */
	if (!sc->vsc_rx_ready || sc->resetting) {
		/*
		 * Drop the packet and try later.
		 */
		pcap_next(sc->vsc_pcap, &ph);
		return;
	}

	/*
	 * Check for available rx buffers
	 */
	vq = &sc->vsc_queues[VTNET_RXQ];
	if (!vq_has_descs(vq)) {
		/*
		 * Drop the packet and try later.  Interrupt on
		 * empty, if that's negotiated.
		 */
		pcap_next(sc->vsc_pcap, &ph);
		vq_endchains(vq, 1);
		return;
	}

	do {
		/*
		 * Get descriptor chain.
		 */
		n = vq_getchain(vq, &idx, iov, VTNET_MAXSEGS, NULL);
		assert(n >= 1 && n <= VTNET_MAXSEGS);

		/*
		 * Get a pointer to the rx header, and use the
		 * data immediately following it for the packet buffer.
		 */
		vrx = iov[0].iov_base;
		riov = rx_iov_trim(iov, &n, sc->rx_vhdrlen);

		len = 0;
		
		const uint8_t *bytes;

		/*
		 * Try to read the next packet from PCAP
		 */

		if ( (bytes = pcap_next(sc->vsc_pcap, &ph)) != NULL ) {
			const uint8_t *p = bytes;
        		const uint8_t *pc = p;
        		int ioidx = 0;
        		size_t remlen = ph.caplen;
        		len = (int)ph.caplen;
			/*
			 * This is a poor man's simulation of readv
			 */
			while ((pc - p < len) && (ioidx < n) && (remlen > 0)) {
				size_t copylen = riov[ioidx].iov_len > remlen ? remlen : riov[ioidx].iov_len;
				memcpy(riov[ioidx].iov_base, pc, copylen);
				remlen -= copylen;
				pc += copylen;
				ioidx++;
			}
		} else {
			/*
			 * pcap_next returned NULL pointer - no more packets to read.
			 */
			/*
			 * No more packets, but still some avail ring
			 * entries.  Interrupt if needed/appropriate.
			 */
			vq_retchain(vq);
			vq_endchains(vq, 0);
			return;
		}

		/*
		 * The only valid field in the rx packet header is the
		 * number of buffers if merged rx bufs were negotiated.
		 */
		memset(vrx, 0, sc->rx_vhdrlen);

		if (sc->rx_merge) {
			struct virtio_net_rxhdr *vrxh;

			vrxh = vrx;
			vrxh->vrh_bufs = 1;
		}

		/*
		 * Release this chain and handle more chains.
		 */
		vq_relchain(vq, idx, ((uint32_t) (len + sc->rx_vhdrlen)));
	} while (vq_has_descs(vq));

	/* Interrupt if needed, including for NOTIFY_ON_EMPTY. */
	vq_endchains(vq, 1);
}

#if USE_MEVENT
static void
pci_vtnet_pcap_callback(UNUSED int fd, UNUSED enum ev_type type, void *param)
{
	struct pci_vtnet_softc *sc = param;

	pthread_mutex_lock(&sc->rx_mtx);
	sc->rx_in_progress = 1;
	pci_vtnet_pcap_rx(sc);
	sc->rx_in_progress = 0;
	pthread_mutex_unlock(&sc->rx_mtx);

}

#else /* !USE_MEVENT */

static void *
pci_vtnet_pcap_select_func(void *vsc) {
	struct pci_vtnet_softc *sc;
	fd_set rfd;

	sc = vsc;

	assert(sc);
	assert(sc->vsc_pcapfd != -1);

	FD_ZERO(&rfd);
	FD_SET(sc->vsc_pcapfd, &rfd);

	while (1) {
		if (select((sc->vsc_pcapfd + 1), &rfd, NULL, NULL, NULL) == -1) {
			abort();
		}

		pthread_mutex_lock(&sc->rx_mtx);
		sc->rx_in_progress = 1;
		pci_vtnet_pcap_rx(sc);
		sc->rx_in_progress = 0;
		pthread_mutex_unlock(&sc->rx_mtx);
	}

	return (NULL);
}
#endif

static void
pci_vtnet_ping_rxq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * A qnotify means that the rx process can now begin
	 */
	if (sc->vsc_rx_ready == 0) {
		sc->vsc_rx_ready = 1;
		vq->vq_used->vu_flags |= VRING_USED_F_NO_NOTIFY;
	}
}

static void
pci_vtnet_proctx(struct pci_vtnet_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTNET_MAXSEGS + 1];
	int i, n;
	int plen, tlen;
	uint16_t idx;

	/*
	 * Obtain chain of descriptors.  The first one is
	 * really the header descriptor, so we need to sum
	 * up two lengths: packet length and transfer length.
	 */
	n = vq_getchain(vq, &idx, iov, VTNET_MAXSEGS, NULL);
	assert(n >= 1 && n <= VTNET_MAXSEGS);
	plen = 0;
	tlen = (int) iov[0].iov_len;
	for (i = 1; i < n; i++) {
		plen += iov[i].iov_len;
		tlen += iov[i].iov_len;
	}

	DPRINTF(("virtio: packet send, %d bytes, %d segs\n\r", plen, n));
	pci_vtnet_pcap_tx(sc, &iov[1], n - 1, plen);

	/* chain is processed, release it and set tlen */
	vq_relchain(vq, idx, ((uint32_t) tlen));
}

static void
pci_vtnet_ping_txq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * Any ring entries to process?
	 */
	if (!vq_has_descs(vq))
		return;

	/* Signal the tx thread for processing */
	pthread_mutex_lock(&sc->tx_mtx);
	vq->vq_used->vu_flags |= VRING_USED_F_NO_NOTIFY;
	if (sc->tx_in_progress == 0)
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * Thread which will handle processing of TX desc
 */
static void *
pci_vtnet_tx_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct vqueue_info *vq;
	int error;

	vq = &sc->vsc_queues[VTNET_TXQ];

	/*
	 * Let us wait till the tx queue pointers get initialised &
	 * first tx signaled
	 */
	pthread_mutex_lock(&sc->tx_mtx);
	error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
	assert(error == 0);

	for (;;) {
		/* note - tx mutex is locked here */
		while (sc->resetting || !vq_has_descs(vq)) {
			vq->vq_used->vu_flags &= ~VRING_USED_F_NO_NOTIFY;
			mb();
			if (!sc->resetting && vq_has_descs(vq))
				break;

			sc->tx_in_progress = 0;
			error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
			assert(error == 0);
		}
		vq->vq_used->vu_flags |= VRING_USED_F_NO_NOTIFY;
		sc->tx_in_progress = 1;
		pthread_mutex_unlock(&sc->tx_mtx);

		do {
			/*
			 * Run through entries, placing them into
			 * iovecs and sending when an end-of-packet
			 * is found
			 */
			pci_vtnet_proctx(sc, vq);
		} while (vq_has_descs(vq));

		/*
		 * Generate an interrupt if needed.
		 */
		vq_endchains(vq, 1);

		pthread_mutex_lock(&sc->tx_mtx);
	}
}

#ifdef notyet
static void
pci_vtnet_ping_ctlq(void *vsc, struct vqueue_info *vq)
{

	DPRINTF(("vtnet: control qnotify!\n\r"));
}
#endif

static int
pci_vtnet_parsemac(char *mac_str, uint8_t *mac_addr)
{
        struct ether_addr *ea;
        char *tmpstr;
        char zero_addr[ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };

        tmpstr = strsep(&mac_str,"=");
       
        if ((mac_str != NULL) && (!strcmp(tmpstr,"mac"))) {
                ea = ether_aton(mac_str);

                if (ea == NULL || ETHER_IS_MULTICAST(ea->octet) ||
                    memcmp(ea->octet, zero_addr, ETHER_ADDR_LEN) == 0) {
			fprintf(stderr, "Invalid MAC %s\n", mac_str);
                        return (EINVAL);
                } else
                        memcpy(mac_addr, ea->octet, ETHER_ADDR_LEN);
        }

        return (0);
}

#define CHUNK_SZ 20480

static pcap_t *attach_pcap_with_filter(char *dev, char *filter)
{
  char errbuf[PCAP_ERRBUF_SIZE] = "";

  pcap_t *pcap = pcap_open_live(dev, CHUNK_SZ, 1, 1, errbuf);

  if (pcap) {
    if (filter) {
      struct bpf_program bpf;
      int res = pcap_compile(pcap, &bpf, filter, 0, PCAP_NETMASK_UNKNOWN);
      if (res) {
        return NULL;
      }
      res = pcap_setfilter(pcap, &bpf);
      if (res) {
        return NULL;
      }
    }
    pcap_setdirection(pcap, PCAP_D_IN);
    return pcap;
  } else {
    return NULL;
  }
}



static int
pci_vtnet_init(struct pci_devinst *pi, char *opts)
{
	MD5_CTX mdctx;
	unsigned char digest[16];
	char nstr[80];
	struct pci_vtnet_softc *sc;
	char *devname;
	char *vtopts;
	int mac_provided;
#if !USE_MEVENT
	pthread_t sthrd;
#endif

	sc = calloc(1, sizeof(struct pci_vtnet_softc));

	pthread_mutex_init(&sc->vsc_mtx, NULL);

	vi_softc_linkup(&sc->vsc_vs, &vtnet_vi_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	sc->vsc_queues[VTNET_RXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_RXQ].vq_notify = pci_vtnet_ping_rxq;
	sc->vsc_queues[VTNET_TXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_TXQ].vq_notify = pci_vtnet_ping_txq;
#ifdef notyet
	sc->vsc_queues[VTNET_CTLQ].vq_qsize = VTNET_RINGSZ;
        sc->vsc_queues[VTNET_CTLQ].vq_notify = pci_vtnet_ping_ctlq;
#endif
 
	/*
	 * Attempt to open the PCAP on the device and read the MAC address
	 * if specified
	 */
	mac_provided = 0;
	sc->vsc_pcapfd = -1;
	sc->vsc_pcap = NULL;
	if (opts != NULL) {
		char tbuf[80];
		int err;

		devname = vtopts = strdup(opts);
		(void) strsep(&vtopts, ",");

		if (vtopts != NULL) {
			err = pci_vtnet_parsemac(vtopts, sc->vsc_config.mac);
			if (err != 0) {
				free(devname);
				return (err);
			}
			mac_provided = 1;
		}

		strcpy(tbuf, "");
		strlcat(tbuf, devname, sizeof(tbuf));

		free(devname);

		sc->vsc_pcap = attach_pcap_with_filter(tbuf, "");
		if (sc->vsc_pcap == NULL) {
			WPRINTF(("open of PCAP on device %s failed\n", tbuf));
		} else {
			/*
			 * Set non-blocking and register for read
			 * notifications with the event loop
			 */
			int opt = 1;
			sc->vsc_pcapfd = pcap_fileno(sc->vsc_pcap);
			if (ioctl(sc->vsc_pcapfd, FIONBIO, &opt) < 0) {
				WPRINTF(("PCAP file descriptor O_NONBLOCK failed\n"));
				close(sc->vsc_pcapfd);
				pcap_close(sc->vsc_pcap);
				sc->vsc_pcapfd = -1;
				sc->vsc_pcap = NULL;
			}

#if USE_MEVENT
			sc->vsc_mevp = mevent_add(sc->vsc_pcapfd,
						  EVF_READ,
						  pci_vtnet_pcap_callback,
						  sc);
			if (sc->vsc_mevp == NULL) {
				WPRINTF(("Could not register event\n"));
				close(sc->vsc_pcapfd);
				pcap_close(sc->vsc_pcap);
				sc->vsc_pcapfd = -1;
				sc->vsc_pcap = NULL;
			}

#else /* !USE_MEVENT */
			if (pthread_create(&sthrd, NULL, pci_vtnet_pcap_select_func, sc)) {
				WPRINTF(("Could not create PCAP receive thread\n"));
				close(sc->vsc_pcapfd);
				pcap_close(sc->vsc_pcap);
				sc->vsc_pcapfd = -1;
				sc->vsc_pcap = NULL;
			}
#endif
		}
	}

	/*
	 * The default MAC address is the standard NetApp OUI of 00-a0-98,
	 * followed by an MD5 of the PCI slot/func number and dev name
	 */
	if (!mac_provided) {
		snprintf(nstr, sizeof(nstr), "%d-%d-%s", pi->pi_slot,
		    pi->pi_func, vmname);

		MD5Init(&mdctx);
		MD5Update(&mdctx, nstr, ((unsigned int) strlen(nstr)));
		MD5Final(digest, &mdctx);

		sc->vsc_config.mac[0] = 0x00;
		sc->vsc_config.mac[1] = 0xa0;
		sc->vsc_config.mac[2] = 0x98;
		sc->vsc_config.mac[3] = digest[0];
		sc->vsc_config.mac[4] = digest[1];
		sc->vsc_config.mac[5] = digest[2];
	}

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_NET);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	/* Link is up if we managed to open PCAP on the device. */
	sc->vsc_config.status = (opts == NULL || sc->vsc_pcap != NULL);
	
	/* use BAR 1 to map MSI-X table and PBA, if we're using MSI-X */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		return (1);

	/* use BAR 0 to map config regs in IO space */
	vi_set_io_bar(&sc->vsc_vs, 0);

	sc->resetting = 0;

	sc->rx_merge = 1;
	sc->rx_vhdrlen = sizeof(struct virtio_net_rxhdr);
	sc->rx_in_progress = 0;
	pthread_mutex_init(&sc->rx_mtx, NULL); 

	/* 
	 * Initialize tx semaphore & spawn TX processing thread.
	 * As of now, only one thread for TX desc processing is
	 * spawned. 
	 */
	sc->tx_in_progress = 0;
	pthread_mutex_init(&sc->tx_mtx, NULL);
	pthread_cond_init(&sc->tx_cond, NULL);
	pthread_create(&sc->tx_tid, NULL, pci_vtnet_tx_thread, (void *)sc);
	return (0);
}

static int
pci_vtnet_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	if (offset < 6) {
		assert(offset + size <= 6);
		/*
		 * The driver is allowed to change the MAC address
		 */
		ptr = &sc->vsc_config.mac[offset];
		memcpy(ptr, &value, size);
	} else {
		/* silently ignore other writes */
		DPRINTF(("vtnet: write to readonly reg %d\n\r", offset));
	}

	return (0);
}

static int
pci_vtnet_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	ptr = (uint8_t *)&sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static void
pci_vtnet_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtnet_softc *sc = vsc;

	sc->vsc_features = negotiated_features;

	if (!(sc->vsc_features & VIRTIO_NET_F_MRG_RXBUF)) {
		sc->rx_merge = 0;
		/* non-merge rx header is 2 bytes shorter */
		sc->rx_vhdrlen -= 2;
	}
}

static struct pci_devemu pci_de_vnet_pcap = {
	.pe_emu = 	"virtio-pcap",
	.pe_init =	pci_vtnet_init,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read
};
PCI_EMUL_SET(pci_de_vnet_pcap);
