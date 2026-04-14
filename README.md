# znitch

> This project has been entirely developed by Claude Opus 4.6

eBPF-based network monitor that detects outgoing connections and port bindings,
displaying desktop notifications in real-time.

## Features

- Detects outgoing TCP connections with process name and resolved domain
- Detects port bindings (servers starting to listen)
- DNS query snooping to show domain names instead of raw IPs
- Deduplication of rapid connection attempts (e.g. Happy Eyeballs)

## Dependencies

**Build-time:**

- [Zig](https://ziglang.org/) 0.14.x, 0.15.x, or master

All dependencies (libbpf, libelf, zlib) are fetched automatically by the Zig
build system. D-Bus notifications are implemented natively in Zig with no
external library dependency.

**Runtime:**

- Linux kernel 5.8+ with BPF support (`CONFIG_BPF_SYSCALL=y`)
- A notification daemon (e.g. dunst, mako, swaync)

## Build
 
```
zig build
```

## Run  
   
znitch needs BPF capabilities to load eBPF programs into the kernel.
  
**Option 1: Linux capabilities (recommended)** 
  
```  
sudo setcap cap_bpf,cap_perfmon=ep ./zig-out/bin/znitch
./zig-out/bin/znitch
```
 
> Note: if your system has `kernel.unprivileged_bpf_disabled=2` (common on
  Debian/Ubuntu), `cap_bpf`/`cap_perfmon` won't work. Use `cap_sys_admin`
  instead, or use sudo.
 
**Option 2: sudo**
 
```
sudo ./zig-out/bin/znitch
```
 
When running via sudo, znitch automatically drops privileges after loading BPF
programs so that D-Bus notifications reach your desktop session.

## Usage

```
Usage: znitch [OPTIONS]

Options:
  --timeout <ms>  Notification timeout for connections (default: 5000)
  --help, -h      Show this help
```

## Example output

```
[dns] systemd-resolve (pid 2443) resolving www.google.com
[connect] curl (pid 12345) -> www.google.com (142.251.156.119):443
[bind] python3 (pid 12400) binding 0.0.0.0:8000
[unbind] python3 (pid 12400) closed port 8000
```

## Test

```
zig build test
```

## License

MIT
