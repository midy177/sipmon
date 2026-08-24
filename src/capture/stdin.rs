use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{CaptureSource, pcap_ts_us};

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

    fn next_frame(&mut self, f: &mut dyn FnMut(u64, u32, &[u8])) -> bool {
        if self
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
        {
            return false;
        }
        const BATCH: usize = 256;
        let mut delivered = 0usize;
        while delivered < BATCH {
            match self.cap.next_packet() {
                Ok(pkt) => {
                    f(pcap_ts_us(pkt.header), self.linktype, pkt.data);
                    delivered += 1;
                }
                Err(pcap::Error::NoMorePackets) => return delivered > 0,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "stdin capture error, stopping");
                    return false;
                }
            }
        }
        true
    }
}
