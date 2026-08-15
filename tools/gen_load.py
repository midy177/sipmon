#!/usr/bin/env python3
"""Generate synthetic SIP+RTP+RTCP load pcaps for sipmon performance testing.

Usage:
  python3 tools/gen_load.py -o big.pcap --calls 500 --talk 30 --spread 60
  python3 tools/gen_load.py -o paced.pcap --calls 100 --talk 20 --spread 25

Each call: INVITE/100/200/ACK -> bidirectional PCMU RTP (20ms, jitter, loss,
reorder) -> SR+RR exchange (exercises RTT path) -> BYE/200.
"""
import argparse
import ipaddress
import random
import struct

PCAP_MAGIC = 0xA1B2C3D4


class SocketAddr:
    """Minimal socket-address stand-in for the generator."""

    __slots__ = ("ip", "port")

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __hash__(self):
        return hash((self.ip, self.port))


def pcap_global_header():
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)


def pcap_record(ts_us, data):
    sec = ts_us // 1_000_000
    usec = ts_us % 1_000_000
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


def eth_ip_udp(payload, src_ip, dst_ip, sport, dport):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0, 0, 64, 17, 0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + udp


def rtp(pt, seq, ts, ssrc, payload_len=160):
    return struct.pack(">BBHII", 0x80, pt, seq, ts, ssrc) + bytes(
        (seq * 7 + i) & 0xFF for i in range(payload_len)
    )


def rtcp_sr(ssrc, ntp_s, ntp_f, rtp_ts, pkts, octets):
    body = struct.pack(">IIIII", ssrc, ntp_s, ntp_f, rtp_ts, pkts) + struct.pack(">I", octets)
    return struct.pack(">BBH", 0x80, 200, 6) + body


def rtcp_rr(ssrc, rep_ssrc, lsr, dlsr, fl=0, cum=0, hs=0, jit=0):
    hdr = struct.pack(">BBH", 0x81, 201, 7) + struct.pack(">I", ssrc)
    block = struct.pack(">IBBIII", rep_ssrc, fl, (cum >> 16) & 0xFF, cum & 0xFFFF, hs, jit) + struct.pack(
        ">II", lsr, dlsr
    )
    # fix: cumulative lost is 3 bytes, not (B, HH) — build properly below
    block = struct.pack(">I", rep_ssrc) + bytes([fl, (cum >> 16) & 0xFF, (cum >> 8) & 0xFF, cum & 0xFF]) + \
        struct.pack(">IIII", hs, jit, lsr, dlsr)
    return hdr + block


def ntp_mid32(unix_us):
    secs = unix_us // 1_000_000 + 2_208_988_800
    frac = (unix_us % 1_000_000) / 1_000_000
    mid = int((secs + frac) * 65536.0) & 0xFFFFFFFF
    return mid


# ---------------- TURN (RFC 5766) helpers ----------------

def stun_msg(typ, txn, attrs):
    body = b""
    for at, av in attrs:
        body += struct.pack(">HH", at, len(av)) + av
        while len(body) % 4 != 0:
            body += b"\x00"
    return struct.pack(">HH4s", typ, len(body), struct.pack(">I", 0x2112A442)) + txn + body


def xor_addr_attr(attr_type, addr, txn):
    key = struct.pack(">I", 0x2112A442) + txn
    ip = ipaddress.IPv4Address(addr.ip)
    xport = addr.port ^ (0x2112A442 >> 16)
    val = b"\x00\x01" + struct.pack(">H", xport)
    for i in range(4):
        val += bytes([ip.packed[i] ^ key[i]])
    return (attr_type, val)


def build_turn_call_events(rng, call, turn_ip, t0, talk_s, client_loss, peer_loss):
    """A TURN-relayed call: SIP over the control channel, media via a relay.

    Client (10.30.c) <-> TURN server (203.0.113.1) control on :3478.
    Media leg A (client<->relay addr) carries RTP in ChannelData with
    client-side loss; media leg B (relay<->peer) carries direct RTP with a
    different (peer-side) loss, so the two legs diverge -> imbalance diag.
    """
    client_ip = f"10.30.{call // 250}.{(call % 250) + 1}"
    peer_ip = f"10.40.{call // 250}.{(call % 250) + 1}"
    ctrl_c, ctrl_s = 35000 + call, 3478
    relay_port = 40000 + call
    client_port = 30000 + call * 2
    peer_port = 32000 + call * 2
    call_id = f"turn-{call:05d}@relay.test"
    ssrc_c = 0x50000 + call
    ssrc_p = 0x60000 + call
    txn = struct.pack(">I", 0x1000 + call) + b"\x00" * 8

    sdp_c = (
        f"v=0\r\no=- {call} 1 IN IP4 {client_ip}\r\ns=-\r\nc=IN IP4 {client_ip}\r\nt=0 0\r\n"
        f"m=audio {client_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    ).encode()
    # Peer advertises its own address (direct to peer's media via relay).
    sdp_p = (
        f"v=0\r\no=- {call} 2 IN IP4 {peer_ip}\r\ns=-\r\nc=IN IP4 {peer_ip}\r\nt=0 0\r\n"
        f"m=audio {peer_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    ).encode()
    tag_c, tag_p = f"tc{call}", f"tp{call}"
    branch = f"z9hG4bKturn{call}"

    ev = []

    def sip_frame(payload, src, dst, sp, dp):
        return eth_ip_udp(payload, src, dst, sp, dp)

    invite = sip_msg(
        [
            f"INVITE sip:peer@{peer_ip} SIP/2.0",
            f"Via: SIP/2.0/UDP {client_ip}:{ctrl_c};branch={branch}",
            f"From: <sip:caller{call}@relay.test>;tag={tag_c}",
            f"To: <sip:peer{call}@relay.test>",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
        ],
        sdp_c,
    )
    ev.append((t0, sip_frame(invite, client_ip, peer_ip, ctrl_c, 5060)))
    ev.append((t0 + 2_000, sip_frame(
        sip_msg(["SIP/2.0 100 Trying", f"Call-ID: {call_id}", "CSeq: 1 INVITE"]),
        peer_ip, client_ip, 5060, ctrl_c)))
    ok200 = sip_msg(
        [
            "SIP/2.0 200 OK",
            f"Via: SIP/2.0/UDP {client_ip}:{ctrl_c};branch={branch}",
            f"From: <sip:caller{call}@relay.test>;tag={tag_c}",
            f"To: <sip:peer{call}@relay.test>;tag={tag_p}",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
        ],
        sdp_p,
    )
    ev.append((t0 + 10_000, sip_frame(ok200, peer_ip, client_ip, 5060, ctrl_c)))
    ev.append((t0 + 11_000, sip_frame(
        sip_msg([
            f"ACK sip:peer@{peer_ip} SIP/2.0",
            f"Call-ID: {call_id}", "CSeq: 1 ACK",
        ]),
        client_ip, peer_ip, ctrl_c, 5060)))

    # --- TURN allocation over the control channel (client -> server :3478) ---
    ev.append((t0 + 20_000, sip_frame(
        stun_msg(0x0003, txn, [(0x0006, b"user")]), client_ip, turn_ip, ctrl_c, ctrl_s)))
    relayed = SocketAddr(turn_ip, relay_port)
    ev.append((t0 + 25_000, sip_frame(
        stun_msg(0x0103, txn, [
            xor_addr_attr(0x0016, relayed, txn),
            (0x000D, struct.pack(">I", 600)),
        ]),
        turn_ip, client_ip, ctrl_s, ctrl_c)))

    # --- ChannelBind: channel 0x4001 <-> peer media endpoint ---
    ch = 0x4001
    peer_sa = SocketAddr(peer_ip, peer_port)
    ev.append((t0 + 30_000, sip_frame(
        stun_msg(0x0109, txn, [
            (0x000C, struct.pack(">HH", ch, 0)),
            xor_addr_attr(0x0012, peer_sa, txn),
        ]),
        client_ip, turn_ip, ctrl_c, ctrl_s)))

    # --- Media leg A: client -> relay, RTP wrapped in ChannelData ---
    n = int(talk_s * 50)
    media_start = t0 + 35_000
    seq = 1000
    rts = 16000
    for i in range(n):
        if rng.random() < client_loss:
            seq += 1
            rts += 160
            continue
        inner = rtp(0, seq, rts, ssrc_c)
        ch_frame = struct.pack(">HH", ch, len(inner)) + inner
        ev.append((media_start + i * 20_000 + rng.randrange(-2000, 2000),
                   eth_ip_udp(ch_frame, client_ip, turn_ip, client_port, relay_port)))
        seq = (seq + 1) & 0xFFFF
        rts += 160

    # --- Media leg B: relay -> peer, direct RTP, different (peer-side) loss ---
    seq = 5000
    rts = 32000
    for i in range(n):
        if rng.random() < peer_loss:
            seq += 1
            rts += 160
            continue
        ev.append((media_start + i * 20_000 + rng.randrange(-2000, 2000),
                   eth_ip_udp(rtp(0, seq, rts, ssrc_p), turn_ip, peer_ip, relay_port, peer_port)))
        seq = (seq + 1) & 0xFFFF
        rts += 160

    # --- Teardown ---
    bye_t = media_start + int(talk_s * 1_000_000) + 20_000
    bye = sip_msg(
        [
            f"BYE sip:peer@{peer_ip} SIP/2.0",
            f"Call-ID: {call_id}", "CSeq: 2 BYE",
        ]
    )
    ev.append((bye_t, sip_frame(bye, client_ip, peer_ip, ctrl_c, 5060)))
    ev.append((bye_t + 1_000, sip_frame(
        sip_msg(["SIP/2.0 200 OK", f"Call-ID: {call_id}", "CSeq: 2 BYE"]),
        peer_ip, client_ip, 5060, ctrl_c)))

    ev.sort(key=lambda e: e[0])
    return ev


def sip_msg(lines, body=b""):
    body = body or b""
    head = "\r\n".join(lines)
    return (head + f"\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body


def build_call_events(rng, call, base_ip_a, base_ip_b, t0, talk_s, loss_p, reorder_p):
    """Yield (ts_us, frame_bytes) for one synthetic call."""
    ip_a = f"{base_ip_a}.{(call // 250) % 250}.{(call % 250) + 1}"
    ip_b = f"{base_ip_b}.{(call // 250) % 250}.{(call % 250) + 1}"
    port_a = 20000 + (call % 40000) * 2
    port_b = 30000 + (call % 30000) * 2
    sip_a, sip_b = 5060, 5060
    call_id = f"perf-{call:06d}@load.test"
    ssrc_a = 0x10000 + call
    ssrc_b = 0x80000 + call
    sdp_a = (
        f"v=0\r\no=- {call} 1 IN IP4 {ip_a}\r\ns=-\r\nc=IN IP4 {ip_a}\r\nt=0 0\r\n"
        f"m=audio {port_a} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    ).encode()
    sdp_b = (
        f"v=0\r\no=- {call} 2 IN IP4 {ip_b}\r\ns=-\r\nc=IN IP4 {ip_b}\r\nt=0 0\r\n"
        f"m=audio {port_b} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    ).encode()
    tag_a, tag_b = f"ta{call}", f"tb{call}"
    branch_i = f"z9hG4bKinv{call}"
    branch_b = f"z9hG4bKbye{call}"

    ev = []  # (ts_us, frame)

    invite = sip_msg(
        [
            f"INVITE sip:callee@{ip_b} SIP/2.0",
            f"Via: SIP/2.0/UDP {ip_a}:{sip_a};branch={branch_i}",
            f"From: <sip:caller{call}@load.test>;tag={tag_a}",
            f"To: <sip:callee{call}@load.test>",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
        ],
        sdp_a,
    )
    ev.append((t0, eth_ip_udp(invite, ip_a, ip_b, sip_a, sip_b)))
    ev.append((t0 + 2_000, eth_ip_udp(
        sip_msg(["SIP/2.0 100 Trying", f"Call-ID: {call_id}", "CSeq: 1 INVITE"]), ip_b, ip_a, sip_b, sip_a)))
    ok200 = sip_msg(
        [
            "SIP/2.0 200 OK",
            f"Via: SIP/2.0/UDP {ip_a}:{sip_a};branch={branch_i}",
            f"From: <sip:caller{call}@load.test>;tag={tag_a}",
            f"To: <sip:callee{call}@load.test>;tag={tag_b}",
            f"Call-ID: {call_id}",
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
        ],
        sdp_b,
    )
    ev.append((t0 + 10_000, eth_ip_udp(ok200, ip_b, ip_a, sip_b, sip_a)))
    ack = sip_msg(
        [
            f"ACK sip:callee@{ip_b} SIP/2.0",
            f"Via: SIP/2.0/UDP {ip_a}:{sip_a};branch={branch_i}ack",
            f"From: <sip:caller{call}@load.test>;tag={tag_a}",
            f"To: <sip:callee{call}@load.test>;tag={tag_b}",
            f"Call-ID: {call_id}",
            "CSeq: 1 ACK",
        ]
    )
    ev.append((t0 + 11_000, eth_ip_udp(ack, ip_a, ip_b, sip_a, sip_b)))

    # RTP both directions: 20ms spacing, ±2ms jitter, ~1% loss, occasional reorder.
    n = int(talk_s * 50)
    media_start = t0 + 15_000
    pkt = []
    for direction in (0, 1):
        seq = rng.randrange(0, 65000)
        rts = rng.randrange(0, 0xFFFF)
        src, dst, sp, dp, ssrc = (
            (ip_a, ip_b, port_a, port_b, ssrc_a) if direction == 0
            else (ip_b, ip_a, port_b, port_a, ssrc_b)
        )
        for i in range(n):
            if rng.random() < loss_p:
                seq = (seq + 1) & 0xFFFF
                rts += 160
                continue
            jitter = rng.randrange(-2000, 2000)
            ts_us = media_start + i * 20_000 + jitter
            frame = eth_ip_udp(rtp(0, seq, rts, ssrc), src, dst, sp, dp)
            pkt.append((ts_us, frame))
            seq = (seq + 1) & 0xFFFF
            rts += 160

    # RTCP: SR from each side mid-call + RR replies with LSR/DLSR (RTT path).
    sr_time = media_start + int(talk_s * 1_000_000) // 2
    for direction, (src, dst, sp, dp, ssrc) in enumerate(
        [(ip_a, ip_b, port_a + 1, port_b + 1, ssrc_a), (ip_b, ip_a, port_b + 1, port_a + 1, ssrc_b)]
    ):
        sr_us = sr_time + direction * 30_000
        # sr_us is absolute unix us; NTP seconds = unix + 70y offset. Keep the
        # fractional part consistent with sr_us so RR arrival times align.
        ntp_s = sr_us // 1_000_000 + 2_208_988_800
        ntp_f = int((sr_us % 1_000_000) * (2**32 / 1_000_000)) & 0xFFFFFFFF
        rtp_ts = int(talk_s * 8000 // 2)
        pkt.append((sr_us, eth_ip_udp(
            rtcp_sr(ssrc, ntp_s, ntp_f, rtp_ts, n // 2, n * 80), src, dst, sp, dp)))
        # Peer replies with RR ~60ms later; DLSR=0.05s, LSR = SR's mid32
        # -> measured RTT ≈ 10ms.
        lsr = int((ntp_s + ntp_f / 2**32) * 65536.0) & 0xFFFFFFFF
        dlsr = int(0.05 * 65536)
        peer = (ip_b, ip_a, port_b + 1, port_a + 1) if direction == 0 else (ip_a, ip_b, port_a + 1, port_b + 1)
        pkt.append((sr_us + 60_000, eth_ip_udp(
            rtcp_rr(ssrc, ssrc, lsr, dlsr), peer[0], peer[1], peer[2], peer[3])))

    bye_t = media_start + int(talk_s * 1_000_000) + 20_000
    bye = sip_msg(
        [
            f"BYE sip:callee@{ip_b} SIP/2.0",
            f"Via: SIP/2.0/UDP {ip_a}:{sip_a};branch={branch_b}",
            f"From: <sip:caller{call}@load.test>;tag={tag_a}",
            f"To: <sip:callee{call}@load.test>;tag={tag_b}",
            f"Call-ID: {call_id}",
            "CSeq: 2 BYE",
        ]
    )
    ev.append((bye_t, eth_ip_udp(bye, ip_a, ip_b, sip_a, sip_b)))
    ok_bye = sip_msg(
        [
            "SIP/2.0 200 OK",
            f"Via: SIP/2.0/UDP {ip_a}:{sip_a};branch={branch_b}",
            f"From: <sip:caller{call}@load.test>;tag={tag_a}",
            f"To: <sip:callee{call}@load.test>;tag={tag_b}",
            f"Call-ID: {call_id}",
            "CSeq: 2 BYE",
        ]
    )
    ev.append((bye_t + 1_000, eth_ip_udp(ok_bye, ip_b, ip_a, sip_b, sip_a)))

    ev.extend(pkt)
    ev.sort(key=lambda e: e[0])
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--calls", type=int, default=100)
    ap.add_argument("--talk", type=float, default=20.0, help="talk seconds per call")
    ap.add_argument("--spread", type=float, default=30.0, help="spread call starts over N seconds")
    ap.add_argument("--loss", type=float, default=0.01, help="RTP loss probability")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--turn", type=int, default=0,
                    help="generate N TURN-relayed calls (media via a learned relay)")
    ap.add_argument("--turn-server", default="203.0.113.1", help="TURN server IP")
    ap.add_argument("--client-loss", type=float, default=0.005,
                    help="loss on client<->relay leg (TURN calls)")
    ap.add_argument("--peer-loss", type=float, default=0.20,
                    help="loss on relay<->peer leg (TURN calls, to show imbalance)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    base_us = 1_800_000_000_000_000  # fixed unix epoch us
    all_events = []
    for call in range(args.calls):
        t0 = base_us + int((call / max(args.calls, 1)) * args.spread * 1_000_000)
        all_events.extend(build_call_events(rng, call, "10.10", "10.20", t0, args.talk, args.loss, 0.005))
    for call in range(args.turn):
        t0 = base_us + int(((call + args.calls) / max(args.calls + args.turn, 1)) * args.spread * 1_000_000)
        all_events.extend(build_turn_call_events(
            rng, call, args.turn_server, t0, args.talk, args.client_loss, args.peer_loss))

    all_events.sort(key=lambda e: e[0])
    with open(args.out, "wb") as f:
        f.write(pcap_global_header())
        for ts_us, frame in all_events:
            # Keep real unix timestamps so RTCP SR NTP matches capture time
            # (RTT/one-way derivation requires the same epoch).
            f.write(pcap_record(ts_us, frame))
    n = len(all_events)
    dur = (all_events[-1][0] - all_events[0][0]) / 1e6 if n else 0
    import os
    print(f"wrote {args.out}: {n} packets, {dur:.1f}s span, {os.path.getsize(args.out)/1e6:.1f} MB, "
          f"avg {n/max(dur,0.001):.0f} pps")


if __name__ == "__main__":
    main()
