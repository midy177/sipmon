use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;

use super::{CaptureSource, RawFrame};

/// Offline capture from a pcap stream on stdin (e.g. `tcpdump -w -`).
///
/// Uses libpcap's `pcap_fopen_offline` via the pcap crate's `from_raw_fd`.
pub struct StdinSource {
    cap: pcap::Capture<pcap::Offline>,
    linktype: u32,
    stop: Option<Arc<AtomicBool>>,
}

impl StdinSource {
    /// # Safety
    /// Takes ownership of stdin (fd 0).
    pub unsafe fn open() -> anyhow::Result<Self> {
        let cap = unsafe {
            pcap::Capture::from_raw_fd(0)
                .map_err(|e| anyhow::anyhow!("open stdin pcap stream: {e}"))?
        };
        let linktype = cap.get_datalink().0 as u32;
        Ok(Self {
            cap,
            linktype,
            stop: None,
        })
    }
}

impl CaptureSource for StdinSource {
    fn set_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
    }

    fn next_frame(&mut self) -> Option<RawFrame> {
        loop {
            if self
                .stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Relaxed))
            {
                return None;
            }
            match self.cap.next_packet() {
                Ok(pkt) => {
                    let header = pkt.header;
                    let ts_us = header.ts.tv_sec as u64 * 1_000_000 + header.ts.tv_usec as u64;
                    return Some(RawFrame {
                        ts_us,
                        linktype: self.linktype,
                        data: Bytes::copy_from_slice(pkt.data),
                    });
                }
                Err(pcap::Error::NoMorePackets) => return None,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "stdin capture error, stopping");
                    return None;
                }
            }
        }
    }
}
