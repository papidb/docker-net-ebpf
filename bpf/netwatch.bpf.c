//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DIR_INGRESS 0
#define DIR_EGRESS  1

struct traffic_key {
    __u64 cgroup_id;
    __u8 direction;
    __u8 pad[7];
};

struct traffic_value {
    __u64 bytes;
    __u64 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct traffic_key);
    __type(value, struct traffic_value);
} stats SEC(".maps");

static __always_inline int count_packet(struct __sk_buff *skb, __u8 direction) {
    struct traffic_key key = {};
    struct traffic_value zero = {};
    struct traffic_value *value;

    key.cgroup_id = bpf_get_current_cgroup_id();
    key.direction = direction;

    value = bpf_map_lookup_elem(&stats, &key);
    if (!value) {
        bpf_map_update_elem(&stats, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&stats, &key);
        if (!value) {
            return 1;
        }
    }

    value->bytes += skb->len;
    value->packets += 1;

    return 1;
}

SEC("cgroup_skb/ingress")
int count_ingress(struct __sk_buff *skb) {
    return count_packet(skb, DIR_INGRESS);
}

SEC("cgroup_skb/egress")
int count_egress(struct __sk_buff *skb) {
    return count_packet(skb, DIR_EGRESS);
}