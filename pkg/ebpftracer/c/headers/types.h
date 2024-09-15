#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <vmlinux_missing.h>

struct config {
  int summary_map_index;
};

#define TASK_COMM_LEN 16

// The PID alone is not enough to uniquely identify a process,
// hence we also throw in the start time.
struct process_identity {
  __u32 pid;
  __u64 pid_start_time;
  __u8 name[TASK_COMM_LEN];
} __attribute__((__packed__));

union addr {
  __u8 raw[16];
  __u32 ipv6[4];
  __be32 ipv4;
} __attribute__((__packed__));

struct network_tuple {
  __u16 lport;
  __u16 dport;
  __u16 family;
  __u32 proto;

  union addr saddr;
  union addr daddr;
} __attribute__((__packed__));

struct ip_key {
  struct process_identity process_identity;

  struct network_tuple tuple;

  // In order for BTF to be generated for this struct, a dummy variable needs to
  // be created.
} __attribute__((__packed__)) ip_key_dummy;

struct traffic_summary {
  size_t rx_packets;
  size_t rx_bytes;

  size_t tx_packets;
  size_t tx_bytes;

  __u64 last_packet_ts;
  // In order for BTF to be generated for this struct, a dummy variable needs to
  // be created.
} __attribute__((__packed__)) traffic_summary_dummy;

enum flow_direction {
  INGRESS,
  EGRESS,
};

#endif
