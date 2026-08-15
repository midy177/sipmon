use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};

use crate::model::packet::{Flow5Tuple, Proto};
use crate::model::stats::{HealthBucket, MetricSet};

pub const MAGIC: &[u8; 4] = b"SMON";
pub const VERSION: u16 = 1;

/// Sanity cap for a single evlog record payload (32 MiB). A length field
/// beyond this means the file is corrupt/hostile; fail cleanly instead of
/// attempting a giant allocation.
pub const MAX_RECORD_LEN: usize = 32 * 1024 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum EvType {
    SipMsg = 1,
    Txn = 2,
    Call = 3,
    StreamSnap = 4,
    RtcpRtt = 5,
    HealthBucket = 6,
    Error = 7,
    Diag = 8,
}

// ----------------------------- payload structs -----------------------------

#[derive(Debug, Clone)]
pub struct SipMsgEvt {
    pub ts_us: u64,
    pub flow: Flow5Tuple,
    pub is_request: bool,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub call_id: String,
    pub cseq: Option<u32>,
    pub branch: Option<String>,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CallEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub kind: CallEvtKind,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub state: u8,
    pub outcome: u8,
    pub invite_ts: Option<u64>,
    pub trying_ts: Option<u64>,
    pub ringing_ts: Option<u64>,
    pub answer_ts: Option<u64>,
    pub bye_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub hangup_code: Option<u32>,
    pub hangup_reason: Option<String>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub pkts_rtcp: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum CallEvtKind {
    Setup = 1,
    Update = 2,
    Teardown = 3,
}

#[derive(Debug, Clone)]
pub struct StreamSnapEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub ssrc: u32,
    pub flow: Flow5Tuple,
    pub codec: Option<String>,
    pub payload_type: Option<u8>,
    pub packets: u64,
    pub lost: u64,
    pub expected: u64,
    pub loss_pct: f64,
    pub jitter_ms: Option<f64>,
    pub mos: Option<f64>,
    pub direction: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RtcpRttEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub ssrc: u32,
    pub rtt_ms: f64,
    pub oneway_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct TxnEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub branch: String,
    pub method: String,
    pub response_code: Option<u16>,
    pub delay_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ErrorEvt {
    pub ts_us: u64,
    pub kind: String,
    pub msg: String,
}

#[derive(Debug, Clone)]
pub struct DiagEvt {
    pub ts_us: u64,
    pub call_id: String,
    pub severity: u8, // 0=info 1=warn 2=critical
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    SipMsg(SipMsgEvt),
    Txn(TxnEvt),
    Call(CallEvt),
    StreamSnap(StreamSnapEvt),
    RtcpRtt(RtcpRttEvt),
    HealthBucket(HealthBucket),
    Error(ErrorEvt),
    Diag(DiagEvt),
}

impl Event {
    pub fn ts_us(&self) -> u64 {
        match self {
            Event::SipMsg(e) => e.ts_us,
            Event::Txn(e) => e.ts_us,
            Event::Call(e) => e.ts_us,
            Event::StreamSnap(e) => e.ts_us,
            Event::RtcpRtt(e) => e.ts_us,
            Event::HealthBucket(e) => e.bucket_us,
            Event::Error(e) => e.ts_us,
            Event::Diag(e) => e.ts_us,
        }
    }
}

// ----------------------------- varint helpers -----------------------------

fn write_varint(buf: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            buf.push(b);
            break;
        } else {
            buf.push(b | 0x80);
        }
    }
}

fn read_varint<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        let b = byte[0];
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
    }
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn write_opt_string(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        Some(s) => {
            // len+1 so 0 encodes None.
            write_varint(buf, s.len() as u64 + 1);
            buf.extend_from_slice(s.as_bytes());
        }
        None => write_varint(buf, 0),
    }
}

fn write_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    write_varint(buf, b.len() as u64);
    buf.extend_from_slice(b);
}

fn write_opt_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(x) => {
            buf.push(1);
            write_varint(buf, x as u64);
        }
        None => buf.push(0),
    }
}

fn write_opt_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(x) => {
            buf.push(1);
            write_varint(buf, x);
        }
        None => buf.push(0),
    }
}

fn write_opt_u16(buf: &mut Vec<u8>, v: Option<u16>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.extend_from_slice(&x.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn write_opt_u8(buf: &mut Vec<u8>, v: Option<u8>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.push(x);
        }
        None => buf.push(0),
    }
}

fn write_opt_f64(buf: &mut Vec<u8>, v: Option<f64>) {
    match v {
        Some(x) => {
            buf.push(1);
            buf.extend_from_slice(&x.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn write_f64(buf: &mut Vec<u8>, v: f64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_flow(buf: &mut Vec<u8>, flow: &Flow5Tuple) {
    buf.push(match flow.proto {
        Proto::Udp => 0,
        Proto::Tcp => 1,
    });
    write_sockaddr(buf, &flow.src);
    write_sockaddr(buf, &flow.dst);
}

fn write_sockaddr(buf: &mut Vec<u8>, sa: &SocketAddr) {
    match sa.ip() {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&sa.port().to_be_bytes());
}

fn encode_event_payload(ev: &Event) -> (EvType, Vec<u8>) {
    let mut buf = Vec::new();
    match ev {
        Event::SipMsg(e) => {
            write_flow(&mut buf, &e.flow);
            buf.push(e.is_request as u8);
            write_opt_string(&mut buf, &e.method);
            write_opt_u16(&mut buf, e.status);
            write_string(&mut buf, &e.call_id);
            write_opt_u32(&mut buf, e.cseq);
            write_opt_string(&mut buf, &e.branch);
            write_opt_string(&mut buf, &e.from_tag);
            write_opt_string(&mut buf, &e.to_tag);
            write_bytes(&mut buf, &e.raw);
            (EvType::SipMsg, buf)
        }
        Event::Txn(e) => {
            write_string(&mut buf, &e.call_id);
            write_string(&mut buf, &e.branch);
            write_string(&mut buf, &e.method);
            write_opt_u16(&mut buf, e.response_code);
            write_opt_u32(&mut buf, e.delay_ms);
            (EvType::Txn, buf)
        }
        Event::Call(e) => {
            write_string(&mut buf, &e.call_id);
            buf.push(e.kind as u8);
            write_opt_string(&mut buf, &e.from_user);
            write_opt_string(&mut buf, &e.to_user);
            write_opt_string(&mut buf, &e.from_uri);
            write_opt_string(&mut buf, &e.to_uri);
            buf.push(e.state);
            buf.push(e.outcome);
            write_opt_u64(&mut buf, e.invite_ts);
            write_opt_u64(&mut buf, e.trying_ts);
            write_opt_u64(&mut buf, e.ringing_ts);
            write_opt_u64(&mut buf, e.answer_ts);
            write_opt_u64(&mut buf, e.bye_ts);
            write_opt_u64(&mut buf, e.end_ts);
            write_opt_u32(&mut buf, e.pdd_ms);
            write_opt_u32(&mut buf, e.setup_ms);
            write_opt_u32(&mut buf, e.hangup_code);
            write_opt_string(&mut buf, &e.hangup_reason);
            write_varint(&mut buf, e.pkts_sip);
            write_varint(&mut buf, e.pkts_rtp);
            write_varint(&mut buf, e.pkts_rtcp);
            write_varint(&mut buf, e.bytes);
            (EvType::Call, buf)
        }
        Event::StreamSnap(e) => {
            write_string(&mut buf, &e.call_id);
            buf.extend_from_slice(&e.ssrc.to_be_bytes());
            write_flow(&mut buf, &e.flow);
            write_opt_string(&mut buf, &e.codec);
            write_opt_u8(&mut buf, e.payload_type);
            write_varint(&mut buf, e.packets);
            write_varint(&mut buf, e.lost);
            write_varint(&mut buf, e.expected);
            write_f64(&mut buf, e.loss_pct);
            write_opt_f64(&mut buf, e.jitter_ms);
            write_opt_f64(&mut buf, e.mos);
            write_opt_string(&mut buf, &e.direction);
            (EvType::StreamSnap, buf)
        }
        Event::RtcpRtt(e) => {
            write_string(&mut buf, &e.call_id);
            buf.extend_from_slice(&e.ssrc.to_be_bytes());
            write_f64(&mut buf, e.rtt_ms);
            write_opt_f64(&mut buf, e.oneway_ms);
            (EvType::RtcpRtt, buf)
        }
        Event::HealthBucket(e) => {
            write_varint(&mut buf, e.bucket_us);
            write_string(&mut buf, &e.dim_key);
            write_metric_set(&mut buf, &e.metrics);
            (EvType::HealthBucket, buf)
        }
        Event::Error(e) => {
            write_string(&mut buf, &e.kind);
            write_string(&mut buf, &e.msg);
            (EvType::Error, buf)
        }
        Event::Diag(e) => {
            write_string(&mut buf, &e.call_id);
            buf.push(e.severity);
            write_string(&mut buf, &e.code);
            write_string(&mut buf, &e.message);
            (EvType::Diag, buf)
        }
    }
}

fn write_metric_set(buf: &mut Vec<u8>, m: &MetricSet) {
    write_varint(buf, m.calls);
    write_varint(buf, m.answered);
    write_varint(buf, m.failed);
    write_f64(buf, m.pdd_sum_ms);
    write_varint(buf, m.pdd_n);
    write_f64(buf, m.jitter_sum_ms);
    write_varint(buf, m.jitter_n);
    write_f64(buf, m.loss_sum_pct);
    write_varint(buf, m.loss_n);
    write_f64(buf, m.rtt_sum_ms);
    write_varint(buf, m.rtt_n);
    write_f64(buf, m.mos_sum);
    write_varint(buf, m.mos_n);
}

// ----------------------------- writer -----------------------------

pub struct EvlogWriter<W: Write + Send> {
    w: BufWriter<W>,
    last_ts: u64,
}

impl EvlogWriter<File> {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .with_context(|| format!("open evlog {}", path.as_ref().display()))?;
        Self::new(file)
    }
}

impl<W: Write + Send> EvlogWriter<W> {
    pub fn new(w: W) -> Result<Self> {
        let mut bw = BufWriter::new(w);
        // Header (only meaningful at start of file; for append we still write a
        // header marker — readers tolerate multiple headers by resyncing).
        bw.write_all(MAGIC)?;
        bw.write_all(&VERSION.to_be_bytes())?;
        bw.write_all(&0u16.to_be_bytes())?; // flags
        bw.write_all(&0i32.to_be_bytes())?; // tz_offset
        bw.flush()?;
        Ok(Self { w: bw, last_ts: 0 })
    }

    pub fn write(&mut self, ev: &Event) -> Result<()> {
        let ts = ev.ts_us();
        let (ty, payload) = encode_event_payload(ev);
        let delta = ts.saturating_sub(self.last_ts);
        let mut rec = Vec::with_capacity(16 + payload.len());
        write_varint(&mut rec, delta);
        rec.push(ty as u8);
        write_varint(&mut rec, payload.len() as u64);
        rec.extend_from_slice(&payload);
        self.w.write_all(&rec)?;
        self.last_ts = ts;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.w.flush()?;
        Ok(())
    }
}

// ----------------------------- reader -----------------------------

fn read_string<R: Read>(r: &mut R) -> Result<String> {
    let len = read_varint(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn read_opt_string<R: Read>(r: &mut R) -> Result<Option<String>> {
    let len = read_varint(r)?;
    if len == 0 {
        return Ok(None);
    }
    let real = len as usize - 1;
    let mut buf = vec![0u8; real];
    r.read_exact(&mut buf)?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let len = read_varint(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_opt_u32<R: Read>(r: &mut R) -> Result<Option<u32>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    Ok(Some(read_varint(r)? as u32))
}

fn read_opt_u64<R: Read>(r: &mut R) -> Result<Option<u64>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    Ok(Some(read_varint(r)?))
}

fn read_opt_u16<R: Read>(r: &mut R) -> Result<Option<u16>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(Some(u16::from_be_bytes(b)))
}

fn read_opt_u8<R: Read>(r: &mut R) -> Result<Option<u8>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(Some(b[0]))
}

fn read_opt_f64<R: Read>(r: &mut R) -> Result<Option<f64>> {
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    if flag[0] == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(Some(f64::from_be_bytes(b)))
}

fn read_f64<R: Read>(r: &mut R) -> Result<f64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(f64::from_be_bytes(b))
}

fn read_flow<R: Read>(r: &mut R) -> Result<Flow5Tuple> {
    let mut pb = [0u8; 1];
    r.read_exact(&mut pb)?;
    let proto = if pb[0] == 1 { Proto::Tcp } else { Proto::Udp };
    let src = read_sockaddr(r)?;
    let dst = read_sockaddr(r)?;
    Ok(Flow5Tuple { proto, src, dst })
}

fn read_sockaddr<R: Read>(r: &mut R) -> Result<SocketAddr> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let ip = match tag[0] {
        4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            IpAddr::V4(Ipv4Addr::from(b))
        }
        _ => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b)?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
    };
    let mut p = [0u8; 2];
    r.read_exact(&mut p)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
}

fn read_metric_set<R: Read>(r: &mut R) -> Result<MetricSet> {
    Ok(MetricSet {
        calls: read_varint(r)?,
        answered: read_varint(r)?,
        failed: read_varint(r)?,
        pdd_sum_ms: read_f64(r)?,
        pdd_n: read_varint(r)?,
        jitter_sum_ms: read_f64(r)?,
        jitter_n: read_varint(r)?,
        loss_sum_pct: read_f64(r)?,
        loss_n: read_varint(r)?,
        rtt_sum_ms: read_f64(r)?,
        rtt_n: read_varint(r)?,
        mos_sum: read_f64(r)?,
        mos_n: read_varint(r)?,
    })
}

fn decode_payload(ty: u8, ts_us: u64, mut rd: &[u8]) -> Result<Event> {
    let ev = match ty {
        1 => {
            let flow = read_flow(&mut rd)?;
            let mut b = [0u8; 1];
            rd.read_exact(&mut b)?;
            let is_request = b[0] != 0;
            let method = read_opt_string(&mut rd)?;
            let status = read_opt_u16(&mut rd)?;
            let call_id = read_string(&mut rd)?;
            let cseq = read_opt_u32(&mut rd)?;
            let branch = read_opt_string(&mut rd)?;
            let from_tag = read_opt_string(&mut rd)?;
            let to_tag = read_opt_string(&mut rd)?;
            let raw = read_bytes(&mut rd)?;
            Event::SipMsg(SipMsgEvt {
                ts_us,
                flow,
                is_request,
                method,
                status,
                call_id,
                cseq,
                branch,
                from_tag,
                to_tag,
                raw,
            })
        }
        3 => {
            let call_id = read_string(&mut rd)?;
            let mut kb = [0u8; 1];
            rd.read_exact(&mut kb)?;
            let kind = match kb[0] {
                3 => CallEvtKind::Teardown,
                2 => CallEvtKind::Update,
                _ => CallEvtKind::Setup,
            };
            let from_user = read_opt_string(&mut rd)?;
            let to_user = read_opt_string(&mut rd)?;
            let from_uri = read_opt_string(&mut rd)?;
            let to_uri = read_opt_string(&mut rd)?;
            let mut sb = [0u8; 1];
            rd.read_exact(&mut sb)?;
            let state = sb[0];
            let mut ob = [0u8; 1];
            rd.read_exact(&mut ob)?;
            let outcome = ob[0];
            let invite_ts = read_opt_u64(&mut rd)?;
            let trying_ts = read_opt_u64(&mut rd)?;
            let ringing_ts = read_opt_u64(&mut rd)?;
            let answer_ts = read_opt_u64(&mut rd)?;
            let bye_ts = read_opt_u64(&mut rd)?;
            let end_ts = read_opt_u64(&mut rd)?;
            let pdd_ms = read_opt_u32(&mut rd)?;
            let setup_ms = read_opt_u32(&mut rd)?;
            let hangup_code = read_opt_u32(&mut rd)?;
            let hangup_reason = read_opt_string(&mut rd)?;
            let pkts_sip = read_varint(&mut rd)?;
            let pkts_rtp = read_varint(&mut rd)?;
            let pkts_rtcp = read_varint(&mut rd)?;
            let bytes = read_varint(&mut rd)?;
            Event::Call(CallEvt {
                ts_us,
                call_id,
                kind,
                from_user,
                to_user,
                from_uri,
                to_uri,
                state,
                outcome,
                invite_ts,
                trying_ts,
                ringing_ts,
                answer_ts,
                bye_ts,
                end_ts,
                pdd_ms,
                setup_ms,
                hangup_code,
                hangup_reason,
                pkts_sip,
                pkts_rtp,
                pkts_rtcp,
                bytes,
            })
        }
        4 => {
            let call_id = read_string(&mut rd)?;
            let mut s = [0u8; 4];
            rd.read_exact(&mut s)?;
            let ssrc = u32::from_be_bytes(s);
            let flow = read_flow(&mut rd)?;
            let codec = read_opt_string(&mut rd)?;
            let payload_type = read_opt_u8(&mut rd)?;
            let packets = read_varint(&mut rd)?;
            let lost = read_varint(&mut rd)?;
            let expected = read_varint(&mut rd)?;
            let loss_pct = read_f64(&mut rd)?;
            let jitter_ms = read_opt_f64(&mut rd)?;
            let mos = read_opt_f64(&mut rd)?;
            let direction = read_opt_string(&mut rd)?;
            Event::StreamSnap(StreamSnapEvt {
                ts_us,
                call_id,
                ssrc,
                flow,
                codec,
                payload_type,
                packets,
                lost,
                expected,
                loss_pct,
                jitter_ms,
                mos,
                direction,
            })
        }
        5 => {
            let call_id = read_string(&mut rd)?;
            let mut s = [0u8; 4];
            rd.read_exact(&mut s)?;
            let ssrc = u32::from_be_bytes(s);
            let rtt_ms = read_f64(&mut rd)?;
            let oneway_ms = read_opt_f64(&mut rd)?;
            Event::RtcpRtt(RtcpRttEvt {
                ts_us,
                call_id,
                ssrc,
                rtt_ms,
                oneway_ms,
            })
        }
        6 => {
            let bucket_us = read_varint(&mut rd)?;
            let dim_key = read_string(&mut rd)?;
            let metrics = read_metric_set(&mut rd)?;
            Event::HealthBucket(HealthBucket {
                bucket_us,
                dim_key,
                metrics,
            })
        }
        7 => {
            let kind = read_string(&mut rd)?;
            let msg = read_string(&mut rd)?;
            Event::Error(ErrorEvt { ts_us, kind, msg })
        }
        2 => {
            let call_id = read_string(&mut rd)?;
            let branch = read_string(&mut rd)?;
            let method = read_string(&mut rd)?;
            let response_code = read_opt_u16(&mut rd)?;
            let delay_ms = read_opt_u32(&mut rd)?;
            Event::Txn(TxnEvt {
                ts_us,
                call_id,
                branch,
                method,
                response_code,
                delay_ms,
            })
        }
        8 => {
            let call_id = read_string(&mut rd)?;
            let mut sb = [0u8; 1];
            rd.read_exact(&mut sb)?;
            let severity = sb[0];
            let code = read_string(&mut rd)?;
            let message = read_string(&mut rd)?;
            Event::Diag(DiagEvt {
                ts_us,
                call_id,
                severity,
                code,
                message,
            })
        }
        _ => {
            // Unknown event type from a newer writer: skip transparently.
            Event::Error(ErrorEvt {
                ts_us,
                kind: "unknown_event".into(),
                msg: format!("skipped event type {ty}"),
            })
        }
    };
    Ok(ev)
}

pub struct EvlogReader {
    r: BufReader<Box<dyn Read + Send>>,
    last_ts: u64,
}

impl EvlogReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let f = File::open(path.as_ref())
            .with_context(|| format!("open evlog {}", path.as_ref().display()))?;
        Self::new(f)
    }
}

impl EvlogReader {
    pub fn new(r: impl Read + Send + 'static) -> Result<Self> {
        let mut r = r;
        // Peek 4 bytes to detect/strip the file header.
        let mut head = [0u8; 4];
        let n = r.read(&mut head)?;
        let inner: Box<dyn Read + Send> = if n == 4 && &head == MAGIC {
            // Consume the remaining 8 header bytes (version/flags/tz).
            let mut rest = [0u8; 8];
            let _ = r.read_exact(&mut rest);
            Box::new(r)
        } else {
            Box::new(std::io::Cursor::new(head[..n].to_vec()).chain(r))
        };
        Ok(Self {
            r: BufReader::new(inner),
            last_ts: 0,
        })
    }

    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let delta = match read_varint(&mut self.r) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let ts_us = self.last_ts.saturating_add(delta);
        self.last_ts = ts_us;
        let mut ty = [0u8; 1];
        match self.r.read_exact(&mut ty) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = read_varint(&mut self.r)? as usize;
        if len > MAX_RECORD_LEN {
            anyhow::bail!("evlog record length {len} exceeds cap {MAX_RECORD_LEN} — corrupt file?");
        }
        let mut payload = vec![0u8; len];
        self.r.read_exact(&mut payload)?;
        let ev = decode_payload(ty[0], ts_us, &payload)?;
        Ok(Some(ev))
    }
}

impl Iterator for EvlogReader {
    type Item = Result<Event>;
    fn next(&mut self) -> Option<Result<Event>> {
        match self.next_event() {
            Ok(Some(ev)) => Some(Ok(ev)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&Event::SipMsg(SipMsgEvt {
            ts_us: 1_000_000,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "1.2.3.4:5060".parse().unwrap(),
                dst: "5.6.7.8:5060".parse().unwrap(),
            },
            is_request: true,
            method: Some("INVITE".into()),
            status: None,
            call_id: "abc@host".into(),
            cseq: Some(1),
            branch: Some("z9hG4bKx".into()),
            from_tag: Some("ft".into()),
            to_tag: None,
            raw: b"INVITE sip:bob@x SIP/2.0\r\n\r\n".to_vec(),
        }))
        .unwrap();
        w.write(&Event::RtcpRtt(RtcpRttEvt {
            ts_us: 1_500_000,
            call_id: "abc@host".into(),
            ssrc: 42,
            rtt_ms: 23.5,
            oneway_ms: Some(12.0),
        }))
        .unwrap();
        w.flush().unwrap();
        drop(w);

        let mut r = EvlogReader::new(std::io::Cursor::new(buf.clone())).unwrap();
        let e1 = r.next_event().unwrap().unwrap();
        let e2 = r.next_event().unwrap().unwrap();
        assert!(matches!(e1, Event::SipMsg(_)));
        assert!(matches!(e2, Event::RtcpRtt(_)));
        assert_eq!(e1.ts_us(), 1_000_000);
        assert_eq!(e2.ts_us(), 1_500_000);
        assert!(r.next_event().unwrap().is_none());
    }
}
