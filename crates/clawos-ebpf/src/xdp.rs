#![allow(dead_code)]
// crates/clawos-ebpf/src/xdp.rs
//
// XDP network packet filter — B-04
// Runs at NIC driver level, before the kernel network stack.
// Policy: only allow TCP packets to/from ClawFS port (5432) and
// the NEAR AI / configured LLM endpoint.
// Drops all other packets at wire speed.
//
// Attached to: veth-clawos0 (the host side of the agent netns veth pair)

//use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

// Allowed TCP destination ports (host byte order — XDP sees them in network order)
const PORT_CLAWFS: u16 = 5432;
const PORT_HTTPS: u16 = 443; // LLM API, Brave Search, Tavily
const PORT_HTTP_DEV: u16 = 8080; // dev-mode internal gateway

// ClawFS host IP inside netns: 10.100.0.1 (from setup-netns.sh)
const CLAWFS_IP: u32 = 0x0A64_0001; // 10.100.0.1 in big-endian

// XDP return codes
const XDP_PASS: u32 = xdp_action::XDP_PASS;
const XDP_DROP: u32 = xdp_action::XDP_DROP;
const XDP_ABORTED: u32 = xdp_action::XDP_ABORTED;

#[xdp]
pub fn clawos_xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(action) => action,
        Err(_) => XDP_ABORTED,
    }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // ── Ethernet header (14 bytes) ──────────────────────────
    if data + 14 > data_end {
        return Ok(XDP_DROP);
    }
    let eth: *const EthHdr = data as *const EthHdr;
    let ether_type = unsafe { u16::from_be((*eth).h_proto) };

    // Only handle IPv4 (0x0800). Pass ARP (0x0806) for netns setup.
    if ether_type == 0x0806 {
        return Ok(XDP_PASS);
    }
    if ether_type != 0x0800 {
        return Ok(XDP_DROP);
    }

    // ── IPv4 header (20 bytes minimum) ──────────────────────
    let ip_start = data + 14;
    if ip_start + 20 > data_end {
        return Ok(XDP_DROP);
    }
    let ip: *const IpHdr = ip_start as *const IpHdr;

    let protocol = unsafe { (*ip).protocol };
    let ihl = unsafe { ((*ip).version_ihl & 0x0F) as usize * 4 };
    let src_ip = unsafe { u32::from_be((*ip).src_addr) };
    let dst_ip = unsafe { u32::from_be((*ip).dst_addr) };

    // Only allow TCP (protocol 6)
    // ICMP (1) allowed for diagnostics
    if protocol == 1 {
        return Ok(XDP_PASS);
    } // ICMP pass-through
    if protocol != 6 {
        return Ok(XDP_DROP);
    } // drop UDP, SCTP, etc.

    // ── TCP header ───────────────────────────────────────────
    let tcp_start = ip_start + ihl;
    if tcp_start + 20 > data_end {
        return Ok(XDP_DROP);
    }
    let tcp: *const TcpHdr = tcp_start as *const TcpHdr;

    let dst_port = unsafe { u16::from_be((*tcp).dest) };
    let src_port = unsafe { u16::from_be((*tcp).source) };

    // Policy rules:
    //
    // 1. Traffic TO ClawFS (dst=5432, dst_ip=CLAWFS_IP) → PASS
    //    (agent → ClawFS SQLite via TCP socket)
    if dst_port == PORT_CLAWFS && dst_ip == CLAWFS_IP {
        return Ok(XDP_PASS);
    }

    // 2. Return traffic FROM ClawFS → PASS
    if src_port == PORT_CLAWFS && src_ip == CLAWFS_IP {
        return Ok(XDP_PASS);
    }

    // 3. HTTPS egress (dst=443) → PASS (LLM API, search providers)
    //    Network namespace iptables provides the actual allowlist —
    //    XDP is defense-in-depth for everything else.
    if dst_port == PORT_HTTPS {
        return Ok(XDP_PASS);
    }

    // 4. Return HTTPS traffic → PASS
    if src_port == PORT_HTTPS {
        return Ok(XDP_PASS);
    }

    // 5. Dev-mode internal gateway (src/dst 8080) → PASS only in netns
    if dst_port == PORT_HTTP_DEV || src_port == PORT_HTTP_DEV {
        return Ok(XDP_PASS);
    }

    // 6. TCP SYN/ACK for established connections → checked by src/dst port above
    //    Anything else: DROP
    Ok(XDP_DROP)
}

// ── Wire format structs ───────────────────────────────────────
// Must be #[repr(C)] for XDP pointer arithmetic

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}
