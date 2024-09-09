#include "helpers/identity.h"
#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <maps.h>
#include <types.h>

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx) {
  __u32 family = ctx->family;
  switch (family) {
  case AF_INET:
  case AF_INET6:
    break;
  default: // Unsupported
    return 1;
  }

  __u32 protocol = ctx->protocol;
  switch (protocol) {
  case IPPROTO_IP:
  case IPPROTO_IPV6:
  case IPPROTO_TCP:
  case IPPROTO_UDP:
  case IPPROTO_ICMP:
  case IPPROTO_ICMPV6:
    break;
  default: // Unsupported
    return 1;
  }

  struct process_identity *identity = bpf_sk_storage_get(
      &socket_process_identity_map, ctx, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);

  if (identity == NULL) {
    return 1;
  }

  init_process_identity(identity);

  return 1;
}

static __always_inline void update_summary(struct traffic_summary *val,
                                           u64 bytes,
                                           enum flow_direction direction) {
  val->last_packet_ts = bpf_ktime_get_ns();

  switch (direction) {
  case INGRESS:
    __sync_fetch_and_add(&val->rx_bytes, bytes);
    __sync_fetch_and_add(&val->rx_packets, 1);
    break;
  case EGRESS:
    __sync_fetch_and_add(&val->tx_bytes, bytes);
    __sync_fetch_and_add(&val->tx_packets, 1);
    break;
  }
}

static __always_inline void record_flow(struct __sk_buff *ctx,
                                        enum flow_direction direction) {
  struct bpf_sock *sk = ctx->sk;
  if (sk == NULL) {
    return;
  }

  struct process_identity identity = {0};
  struct process_identity *socket_process_identity =
      bpf_sk_storage_get(&socket_process_identity_map, sk, NULL, 0);

  // If the socket doesn't have an processs identity, we just fall back to
  // attribute it to a zero process.
  if (socket_process_identity != NULL) {
    identity = *socket_process_identity;
  }

  int zero = 0;
  struct config *config = bpf_map_lookup_elem(&config_map, &zero);
  if (config == NULL)
    return;

  void *sum_map =
      bpf_map_lookup_elem(&sum_map_buffer, &config->summary_map_index);
  if (sum_map == NULL)
    return;

  struct ip_key key = {0};

  if (!load_ip_key(&key, ctx, identity)) {
    // Something went wrong...
    bpf_printk("something went wrong...");
    return;
  }
  struct traffic_summary *summary = bpf_map_lookup_elem(sum_map, &key);
  if (summary == NULL) {
    struct traffic_summary empty = {0};
    if (bpf_map_update_elem(sum_map, &key, &empty, BPF_NOEXIST) != 0)
      return;

    summary = bpf_map_lookup_elem(sum_map, &key);
    if (summary == NULL) // Something went terribly wrong...
      return;
  }

  update_summary(summary, ctx->len, direction);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx) {
  record_flow(ctx, INGRESS);
  return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx) {
  record_flow(ctx, EGRESS);
  return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
