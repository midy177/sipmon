use std::collections::HashMap;

use crate::model::packet::Flow5Tuple;

/// Content-Length based SIP-over-TCP stream reassembler.
///
/// Buffers bytes per (directed) flow and yields complete SIP messages. This is
/// the M0-grade implementation: it handles the common case of messages split or
/// coalesced within a TCP connection. Full out-of-order/loss recovery is M4.
pub struct TcpReassembler {
    buffers: HashMap<Flow5Tuple, Vec<u8>>,
}

/// Per-flow reassembly buffer cap (1 MiB). A flow exceeding this is considered
/// hostile/misframed and its buffer is dropped — bounds memory under garbage
/// input (e.g. SIP headers advertising a huge Content-Length followed by an
/// endless byte stream).
pub const MAX_STREAM_BUF: usize = 1 << 20;

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Bytes currently buffered across all flows (observable for tests).
    #[cfg(test)]
    pub fn buffered_bytes(&self) -> usize {
        self.buffers.values().map(|b| b.len()).sum()
    }

    /// Feed bytes for a flow; returns zero or more fully framed messages.
    pub fn feed(&mut self, flow: Flow5Tuple, data: &[u8]) -> Vec<Vec<u8>> {
        let buf = self.buffers.entry(flow).or_default();
        buf.extend_from_slice(data);
        if buf.len() > MAX_STREAM_BUF {
            // Poison frame: drop the buffer entirely to bound memory.
            buf.clear();
            return Vec::new();
        }

        let mut out = Vec::new();
        while let Some(sep) = find_double_crlf(buf) {
            let header_end = sep + 4;
            let header_bytes = &buf[..sep];
            let content_length = extract_content_length(header_bytes);
            let total = header_end + content_length;
            if buf.len() < total {
                // Need more bytes for the body.
                break;
            }
            let msg: Vec<u8> = buf.drain(..total).collect();
            out.push(msg);
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
