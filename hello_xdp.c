// Taken from https://gist.github.com/Kamillaova/ae34c680d6ef3ecdc45a9d0d17a886c9
// I think you can interpret the license of this code however you like, as long as the use of some headers does not contradict it, or something like that.

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define __internal static __attribute__((always_inline))

#define xdp_pass return XDP_PASS;
#define xdp_drop return XDP_DROP;
#define xdp_abort return XDP_ABORTED;

__internal int process_tcp(struct tcphdr *tcph) {
	if (tcph->dest == bpf_htons(25565)) {
		xdp_drop
	}

	return -1;
}

SEC("prog")
int xdp_prog(struct xdp_md *ctx) {
	void *data = (void *) (__u64) ctx->data;
	void *data_end = (void *) (__u64) ctx->data_end;

	struct ethhdr *eth = data;

	if (unlikely(eth + 1 > (struct ethhdr *) data_end)) {
		xdp_abort
	}

	struct tcphdr *tcph;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(struct ethhdr);

		if (unlikely(iph + 1 > (struct iphdr *) data_end)) {
			xdp_abort
		}

		if (iph->protocol != IPPROTO_TCP) {
			xdp_pass
		}

		tcph = (void *) iph + (iph->ihl * 4);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h = data + sizeof(struct ethhdr);

		if (unlikely(ipv6h + 1 > (struct ipv6hdr *) data_end)) {
			xdp_abort
		}

		if (ipv6h->nexthdr != IPPROTO_TCP) {
			xdp_pass
		}

		tcph = (void *) ipv6h + sizeof(struct ipv6hdr);
	} else {
		xdp_pass
	}

	if (unlikely(tcph + 1 > (struct tcphdr *) data_end)) {
		xdp_abort
	}

	int ret;
	if ((ret = process_tcp(tcph)) != -1) {
		return ret;
	}

	xdp_pass
}
