#ifndef __IDENTITY_H__
#define __IDENTITY_H__

#include "vmlinux.h"
#include <helpers/ip.h>
#include <types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

static __always_inline void
init_process_identity(struct process_identity *identity) {
  struct task_struct *task = bpf_get_current_task_btf();

  identity->pid = task->pid;
  identity->pid_start_time = task->start_time;
  bpf_get_current_comm(&identity->name, sizeof(identity->name));
}
static __always_inline bool load_network_tuple(struct bpf_sock *sk,
                                               struct network_tuple *tuple) {
  if (tuple == NULL || sk == NULL) {
    return false;
  }

  tuple->proto = sk->protocol;
  tuple->family = sk->family;
  tuple->lport = bpf_ntohs(sk->src_port);
  tuple->dport = bpf_ntohs(sk->dst_port);

  switch (sk->family) {
  case AF_INET:
    tuple->saddr.ipv4 = sk->src_ip4;
    tuple->daddr.ipv4 = sk->dst_ip4;
    break;
  case AF_INET6: {
    __builtin_memcpy(tuple->saddr.ipv6, sk->src_ip6, 4);
    __builtin_memcpy(tuple->daddr.ipv6, sk->dst_ip6, 4);
  } break;
  default:
    return false;
  }

  return true;
}

static __always_inline bool
load_ip_key(struct ip_key *key, struct bpf_sock *sk,
            struct process_identity process_identity) {
  key->process_identity = process_identity;

  if (!load_network_tuple(sk, &key->tuple)) {
    return false;
  }

  return true;
}

#endif // __IDENTITY_H__
