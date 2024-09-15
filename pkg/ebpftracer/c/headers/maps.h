#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"
#include <types.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct config);
  __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 2);
  __type(key, int);
  __array(
      values, struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 10240);
        __type(key, struct ip_key);
        __type(value, struct traffic_summary);
      });
} sum_map_buffer SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
  __type(key, int);
  __type(value, struct process_identity);
} socket_process_identity_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct network_tuple);
  __type(value, struct process_identity);
} existing_socket_identity_map SEC(".maps");

#endif // __MAPS_H__
