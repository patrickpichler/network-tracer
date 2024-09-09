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

static __always_inline bool
load_ip_key(struct ip_key *key, struct __sk_buff *ctx,
            struct process_identity process_identity) {
  struct bpf_sock *sk = ctx->sk;
  if (sk == NULL)
    return false;

  sk = bpf_sk_fullsock(sk);
  if (sk == NULL)
    return false;

  key->process_identity = process_identity;
  key->proto = sk->protocol;
  key->family = sk->family;
  key->lport = bpf_ntohs(sk->src_port);
  key->dport = bpf_ntohs(sk->dst_port);

  switch (sk->family) {
  case AF_INET:
    key->saddr = ctx->local_ip4;
    key->daddr = ctx->remote_ip4;
    break;
  case AF_INET6:
    if (bpf_probe_read_kernel(&key->saddr, sizeof(ctx->local_ip6),
                              ctx->local_ip6) != 0)
      return false;

    if (bpf_probe_read_kernel(&key->daddr, sizeof(ctx->remote_ip6),
                              ctx->remote_ip6) != 0)
      return false;

    break;
  default:
    return false;
  }

  return true;
}

#endif // __IDENTITY_H__
