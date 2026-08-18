use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{CaptureSource, pcap_ts_us};

/// Offline capture from a pcap/pcapng file (libpcap handles both).
pub struct FileSource {
    cap: pcap::Capture<pcap::Offline>,
    linktype: u32,
    /// Optional pacing: deliver at 1/speed of original inter-packet gaps.
    speed: Option<f64>,
    base_real: Option<std::time::Instant>,
    base_cap_us: Option<u64>,
    stop: Option<Arc<AtomicBool>>,
}

impl FileSource {
    pub fn open(path: &str, speed: Option<f64>) -> anyhow::Result<Self> {
        let cap =
            pcap::Capture::from_file(path).map_err(|e| anyhow::anyhow!("open file {path}: {e}"))?;
        let linktype = cap.get_datalink().0 as u32;
        Ok(Self {
            cap,
            linktype,
            speed,
            base_real: None,
            base_cap_us: None,
            stop: None,
        })
    }
}

impl CaptureSource for FileSource {
    fn set_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
    }

    fn next_frame(&mut self, f: &mut dyn FnMut(u64, u32, &[u8])) -> bool {
        loop {
            if self
                .stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Relaxed))
            {
                return false;
            }
            match self.cap.next_packet() {
                Ok(pkt) => {
                    let ts_us = pcap_ts_us(pkt.header);

                    // Optional real-time pacing for offline replay.
                    if let Some(speed) = self.speed {
                        let now = std::time::Instant::now();
                        let (base_real, base_cap) = match (self.base_real, self.base_cap_us) {
                            (Some(r), Some(c)) => (r, c),
                            _ => {
                                self.base_real = Some(now);
                                self.base_cap_us = Some(ts_us);
                                (now, ts_us)
                            }
                        };
                        if speed > 0.0 {
                            let elapsed_cap_us = ts_us.saturating_sub(base_cap);
                            let target = base_real
                                + std::time::Duration::from_micros(
                                    (elapsed_cap_us as f64 / speed) as u64,
                                );
                            let to_wait = target.saturating_duration_since(now);
                            if !to_wait.is_zero() {
                                let ok = match &self.stop {
                                    Some(s) => super::sleep_interruptible(to_wait, s),
                                    None => {
                                        std::thread::sleep(to_wait);
                                        true
                                    }
                                };
                                if !ok {
                                    return false;
                                }
                            }
                        }
                    }

                    f(ts_us, self.linktype, pkt.data);
                    return true;
                }
                Err(pcap::Error::NoMorePackets) => return false,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "file capture error, stopping");
                    return false;
                }
            }
        }
    }
}
