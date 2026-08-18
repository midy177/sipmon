use std::collections::HashMap;

use crate::model::packet::Flow5Tuple;

/// Content-Length based SIP-over-TCP stream reassembler.
///
/// Buffers bytes per (directed) flow and yields complete SIP messages. This is
/// the M0-grade implementation: it handles the common case of messages split or
/// coalesced within a TCP connection. Full out-of-order/loss recovery is M4.
pub struct TcpReassembler {
    buffers: HashMap<Flow5Tuple, FlowBuf>,
}

struct FlowBuf {
    data: Vec<u8>,
    last_us: u64,
}

/// Per-flow reassembly buffer cap (1 MiB). A flow exceeding this is considered
/// hostile/misframed and its buffer is dropped — bounds memory under garbage
/// input (e.g. SIP headers advertising a huge Content-Length followed by an
/// endless byte stream).
pub const MAX_STREAM_BUF: usize = 1 << 20;

/// Idle TCP flows (no bytes) are dropped after this capture-time gap.
pub const IDLE_US: u64 = 60_000_000;

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Bytes currently buffered across all flows (observable for tests).
    #[cfg(test)]
    pub fn buffered_bytes(&self) -> usize {
        self.buffers.values().map(|b| b.data.len()).sum()
    }

    #[cfg(test)]
    pub fn flow_count(&self) -> usize {
        self.buffers.len()
    }

    /// Drop flows that have been idle for `idle_us` of capture time.
    pub fn prune(&mut self, now_us: u64, idle_us: u64) {
        self.buffers
            .retain(|_, b| now_us.saturating_sub(b.last_us) < idle_us);
    }

    /// Feed bytes for a flow; returns zero or more fully framed messages.
    pub fn feed(&mut self, flow: Flow5Tuple, data: &[u8], ts_us: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut drop_flow = false;
        {
            let buf = self.buffers.entry(flow).or_insert_with(|| FlowBuf {
                data: Vec::new(),
                last_us: ts_us,
            });
            buf.last_us = ts_us;
            buf.data.extend_from_slice(data);
            if buf.data.len() > MAX_STREAM_BUF {
                drop_flow = true;
            } else {
                while let Some(sep) = find_double_crlf(&buf.data) {
                    let header_end = sep + 4;
                    let content_length = extract_content_length(&buf.data[..sep]);
                    let total = header_end + content_length;
                    if buf.data.len() < total {
                        // Need more bytes for the body.
                        break;
                    }
                    let msg: Vec<u8> = buf.data.drain(..total).collect();
                    out.push(msg);
                }
                if buf.data.is_empty() {
                    drop_flow = true;
                }
            }
        }
        if drop_flow {
            self.buffers.remove(&flow);
        }
        out
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn extract_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some((name, val)) = line.split_once(':')
            && (name.trim().eq_ignore_ascii_case("content-length")
                || name.trim().eq_ignore_ascii_case("l"))
        {
            return val.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::{Flow5Tuple, Proto};

    fn flow() -> Flow5Tuple {
        Flow5Tuple {
            proto: Proto::Tcp,
            src: "1.2.3.4:5060".parse().unwrap(),
            dst: "5.6.7.8:5060".parse().unwrap(),
        }
    }

    #[test]
    fn idle_flows_are_pruned() {
        let mut reasm = TcpReassembler::new();
        // Incomplete message: stays buffered.
        reasm.feed(flow(), b"INVITE sip:x SIP/2.0\r\n", 1_000_000);
        assert_eq!(reasm.flow_count(), 1);
        reasm.prune(30_000_000, IDLE_US);
        assert_eq!(reasm.flow_count(), 1);
        reasm.prune(1_000_000 + IDLE_US, IDLE_US);
        assert_eq!(reasm.flow_count(), 0);
    }

    #[test]
    fn complete_message_releases_flow() {
        let mut reasm = TcpReassembler::new();
        let msg = b"INVITE sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let out = reasm.feed(flow(), msg, 1_000_000);
        assert_eq!(out.len(), 1);
        assert_eq!(reasm.flow_count(), 0);
    }
}
