use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{CaptureSource, pcap_ts_us};

/// Live capture from a network interface via libpcap.
pub struct LiveSource {
    cap: pcap::Capture<pcap::Active>,
    linktype: u32,
    stop: Option<Arc<AtomicBool>>,
}

impl LiveSource {
    pub fn open(device: &str, bpf: Option<&str>) -> anyhow::Result<Self> {
        // The Linux "any" pseudo-device captures on all interfaces but does
        // not support promiscuous mode (libpcap rejects it at activation).
        let promisc = device != "any";
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| anyhow::anyhow!("open device {device}: {e}"))?
            .promisc(promisc)
            .snaplen(65535)
            .buffer_size(64 * 1024 * 1024)
            .timeout(100)
            .open()
            .map_err(|e| anyhow::anyhow!("activate device {device}: {e}"))?;

        if let Some(f) = bpf {
            cap.filter(f, true)
                .map_err(|e| anyhow::anyhow!("bpf filter: {e}"))?;
        }

        let linktype = cap.get_datalink().0 as u32;
        Ok(Self {
            cap,
            linktype,
            stop: None,
        })
    }
}

impl CaptureSource for LiveSource {
    fn set_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
    }

    fn pcap_stats(&mut self) -> Option<(u64, u64)> {
        let s = self.cap.stats().ok()?;
        Some((u64::from(s.received), u64::from(s.dropped)))
    }

    fn next_frame(&mut self, f: &mut dyn FnMut(u64, u32, &[u8])) -> bool {
        // Stop is checked per batch, not per frame: 64 frames at multi-Mpps
        // rates complete in microseconds, so shutdown stays prompt.
        if self
            .stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
        {
            return false;
        }
        // Deliver whatever is immediately available, up to BATCH frames. The
        // loop ends at the first would-block (activation timeout), so batch
        // size tracks the NIC queue depth naturally: busy captures fill the
        // batch, sparse ones deliver one frame and return.
        const BATCH: usize = 64;
        let mut delivered = 0usize;
        while delivered < BATCH {
            match self.cap.next_packet() {
                Ok(pkt) => {
                    f(pcap_ts_us(pkt.header), self.linktype, pkt.data);
                    delivered += 1;
                }
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "live capture error, stopping");
                    return false;
                }
            }
        }
        // `true` even when the batch is empty (idle interface): the 100ms
        // activation timeout already paced this call, and the pipeline must
        // not mistake a quiet interface for EOF.
        true
    }
}
