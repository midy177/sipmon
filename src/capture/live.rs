use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;

use super::{CaptureSource, RawFrame};

/// Live capture from a network interface via libpcap.
pub struct LiveSource {
    cap: pcap::Capture<pcap::Active>,
    linktype: u32,
    stop: Option<Arc<AtomicBool>>,
}

impl LiveSource {
    pub fn open(device: &str, bpf: Option<&str>) -> anyhow::Result<Self> {
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| anyhow::anyhow!("open device {device}: {e}"))?
            .promisc(true)
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
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "live capture error, stopping");
                    return None;
                }
            }
        }
    }
}
