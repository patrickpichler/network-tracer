#ifndef __IP_H__
#define __IP_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

static __always_inline unsigned __int128 ipv6_to_int128(__u32 ipv6[4]) {
  unsigned __int128 ret = ipv6[3];
  ret = (ret >> 32) | ipv6[2];
  ret = (ret >> 32) | ipv6[1];
  ret = (ret >> 32) | ipv6[0];

  return ret;
}

#endif // __IP_H__
