// SPDX-License-Identifier: GPL-2.0

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u32 __wsum;
typedef __u32 __sum16;

enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_RINGBUF = 27,
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

#define AF_INET  2
#define AF_INET6 10

struct sockaddr {
    unsigned short sa_family;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  pad[8];
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned int   sin6_flowinfo;
    unsigned char  sin6_addr[16];
    unsigned int   sin6_scope_id;
};

#define EVENT_CONNECT   0
#define EVENT_BIND      1
#define EVENT_UNBIND    2
#define EVENT_DNS_QUERY 3

struct event {
    __u32 pid;
    __u32 uid;
    __u16 port;
    __u16 af;
    __u32 addr_v4;
    __u8  addr_v6[16];
    __u8  event_type;
    char  comm[16];
};

// Raw DNS query bytes — parsed in userspace
#define DNS_RAW_MAX 128

struct dns_query {
    __u8  raw[DNS_RAW_MAX];
    __u32 len;
};

struct pid_fd {
    __u32 pid;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Track fds connected to DNS (port 53)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_fd);
    __type(value, __u8);
} dns_fds SEC(".maps");

// Track fds that called bind()
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pid_fd);
    __type(value, __u16);
} bind_fds SEC(".maps");

// Global most-recent DNS query name (shared across all PIDs).
// Key 0 = most recent query. Written by any process doing DNS.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_query);
} last_dns_query SEC(".maps");

// Per-PID DNS query (for apps that do their own DNS like curl)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct dns_query);
} pid_dns_query SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline int handle_sockaddr(struct trace_event_raw_sys_enter *ctx,
                                           __u8 event_type) {
    struct event *e;
    struct sockaddr sa;
    unsigned long sockaddr_ptr = ctx->args[1];

    if (bpf_probe_read_user(&sa, sizeof(sa), (void *)sockaddr_ptr) < 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), (void *)sockaddr_ptr) < 0)
            return 0;

        __u16 port = bpf_ntohs(sin.sin_port);
        if (port == 0)
            return 0;

        if (port == 53) {
            struct pid_fd key = { .pid = pid, .fd = fd };
            __u8 val = 1;
            bpf_map_update_elem(&dns_fds, &key, &val, 0);
        }

        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        e->event_type = event_type;
        e->pid = pid;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->af = AF_INET;
        e->port = port;
        e->addr_v4 = sin.sin_addr;
        __builtin_memset(&e->addr_v6, 0, sizeof(e->addr_v6));
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);

        if (event_type == EVENT_BIND) {
            struct pid_fd bkey = { .pid = pid, .fd = fd };
            bpf_map_update_elem(&bind_fds, &bkey, &port, 0);
        }
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), (void *)sockaddr_ptr) < 0)
            return 0;

        __u16 port = bpf_ntohs(sin6.sin6_port);
        if (port == 0)
            return 0;

        if (port == 53) {
            struct pid_fd key = { .pid = pid, .fd = fd };
            __u8 val = 1;
            bpf_map_update_elem(&dns_fds, &key, &val, 0);
        }

        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        e->event_type = event_type;
        e->pid = pid;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->af = AF_INET6;
        e->port = port;
        e->addr_v4 = 0;
        __builtin_memcpy(&e->addr_v6, &sin6.sin6_addr, 16);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);

        if (event_type == EVENT_BIND) {
            struct pid_fd bkey = { .pid = pid, .fd = fd };
            bpf_map_update_elem(&bind_fds, &bkey, &port, 0);
        }
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    return handle_sockaddr(ctx, EVENT_CONNECT);
}

SEC("tp/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx) {
    return handle_sockaddr(ctx, EVENT_BIND);
}

// Capture raw DNS query bytes from write()/sendto() on DNS fds.
// Parsing happens in userspace — keeps BPF simple for the verifier.
static __always_inline int capture_dns_query(__u32 fd, const void *buf, __u64 buf_len) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pid_fd key = { .pid = pid, .fd = fd };
    __u8 *is_dns = bpf_map_lookup_elem(&dns_fds, &key);
    if (!is_dns)
        return 0;

    if (buf_len < 13 || buf_len > 512)
        return 0;

    struct dns_query dq = {};
    __u32 copy_len = buf_len < DNS_RAW_MAX ? buf_len : DNS_RAW_MAX;
    if (bpf_probe_read_user(&dq.raw, copy_len & (DNS_RAW_MAX - 1), buf) < 0)
        return 0;
    dq.len = copy_len;

    // Sanity check: byte 12 must be a valid DNS label length (1-63).
    // Rejects TLS/garbage data from reused fds.
    if (dq.raw[12] == 0 || dq.raw[12] > 63)
        return 0;

    bpf_map_update_elem(&pid_dns_query, &pid, &dq, 0);

    __u32 zero = 0;
    bpf_map_update_elem(&last_dns_query, &zero, &dq, 0);

    // Notify userspace about the DNS query
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_DNS_QUERY;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->af = 0;
    e->port = 53;
    e->addr_v4 = 0;
    __builtin_memset(&e->addr_v6, 0, sizeof(e->addr_v6));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
    return capture_dns_query((__u32)ctx->args[0], (const void *)ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    return capture_dns_query((__u32)ctx->args[0], (const void *)ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    struct pid_fd key = { .pid = pid, .fd = fd };

    // Always clean up dns_fds to prevent stale fd reuse capturing garbage
    bpf_map_delete_elem(&dns_fds, &key);

    __u16 *port = bpf_map_lookup_elem(&bind_fds, &key);
    if (!port)
        return 0;

    __u16 bound_port = *port;
    bpf_map_delete_elem(&bind_fds, &key);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_UNBIND;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->af = 0;
    e->port = bound_port;
    e->addr_v4 = 0;
    __builtin_memset(&e->addr_v6, 0, sizeof(e->addr_v6));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
