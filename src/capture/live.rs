use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{CaptureSource, PcapStats, pcap_ts_us};

/// Live capture from a network interface via libpcap.
pub struct LiveSource {
    cap: pcap::Capture<pcap::Active>,
    linktype: u32,
    stop: Option<Arc<AtomicBool>>,
}

impl LiveSource {
    pub fn open(
        device: &str,
        bpf: Option<&str>,
        pcap_buffer_mib: i32,
        snaplen: i32,
    ) -> anyhow::Result<Self> {
        // The Linux "any" pseudo-device captures on all interfaces but does
        // not support promiscuous mode (libpcap rejects it at activation).
        let promisc = device != "any";
        let buffer_bytes = pcap_buffer_mib.saturating_mul(1024 * 1024);
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| anyhow::anyhow!("open device {device}: {e}"))?
            .promisc(promisc)
            .snaplen(snaplen)
            .buffer_size(buffer_bytes)
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

    fn pcap_stats(&mut self) -> Option<PcapStats> {
        let s = self.cap.stats().ok()?;
        Some(PcapStats {
            received: u64::from(s.received),
            dropped: u64::from(s.dropped),
            if_dropped: u64::from(s.if_dropped),
        })
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
        // Deliver a libpcap batch in one syscall; per-packet next_packet()
        // calls increase capture-ring pressure at high packet rates.
        const BATCH: usize = 64;
        match self.cap.dispatch(Some(BATCH), |pkt| {
            f(pcap_ts_us(pkt.header), self.linktype, pkt.data);
        }) {
            Ok(_) => {}
            Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {}
            Err(e) => {
                tracing::warn!(error = %e, "live capture error, stopping");
                return false;
            }
        }
        // `true` even when the batch is empty (idle interface): the 100ms
        // activation timeout already paced this call, and the pipeline must
        // not mistake a quiet interface for EOF.
        true
    }
}
