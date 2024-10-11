#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#if defined(MODE_TC)
#include <linux/pkt_cls.h>

#define u_ctx __sk_buff

#define U_PASS TC_ACT_OK
#define U_DROP TC_ACT_SHOT

#elif defined(MODE_XDP)
#define u_ctx xdp_md

#define U_PASS XDP_PASS
#define U_DROP XDP_DROP
#else
#error Unknown mode, set either -DMODE_TC or -DMODE_XDP
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define __internal static __attribute__((always_inline))

// Unwrap a token or a token value into a string literal
#define MACRO_MKSTRING(x) #x
#define MACRO_TOSTRING(x) MACRO_MKSTRING(x)

// GNU extension that omits file path, use if available
#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif

// Unwraps to example.c@128
#define SOURCE_LINE __FILE_NAME__ "@" MACRO_TOSTRING(__LINE__)

#define pkt_pass return U_PASS;

#define pkt_drop \
	do { \
		bpf_printk("Dropping packet at %s\n", SOURCE_LINE); \
		return U_DROP; \
	} while (0);

#define STUN_MAGIC 0x2112a442

struct stunreq {
	__be16 type;
	__be16 length;
	__be32 magic;
} __packed;

__internal int process_udp(struct udphdr *udph, void *data_end) {
	struct stunreq *req = (void *)(udph + 1);
	if ((void *)(req + 1) > data_end) {
		pkt_pass
	}

	if (bpf_ntohl(req->magic) == STUN_MAGIC) {
		pkt_drop
	}

	return -1;
}

SEC("prog")
int process(struct u_ctx *ctx) {
	void *data = (void *) (__u64) ctx->data;
	void *data_end = (void *) (__u64) ctx->data_end;

	struct ethhdr *eth = data;

	if (unlikely(eth + 1 > (struct ethhdr *) data_end)) {
		pkt_pass
	}

	struct udphdr *udph;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(struct ethhdr);

		if (unlikely(iph + 1 > (struct iphdr *) data_end)) {
			pkt_pass
		}

		if (iph->protocol != IPPROTO_UDP) {
			pkt_pass
		}

		udph = (void *) iph + (iph->ihl * 4);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h = data + sizeof(struct ethhdr);

		if (unlikely(ipv6h + 1 > (struct ipv6hdr *) data_end)) {
			pkt_pass
		}

		if (ipv6h->nexthdr != IPPROTO_UDP) {
			pkt_pass
		}

		udph = (void *) ipv6h + sizeof(struct ipv6hdr);
	} else {
		pkt_pass
	}

	if (unlikely(udph + 1 > (struct udphdr *) data_end)) {
		pkt_pass
	}

	int ret;
	if ((ret = process_udp(udph, data_end)) != -1) {
		return ret;
	}

	pkt_pass
}

char _license[] SEC("license") = "GPL"; // SEE LICENSE.md
