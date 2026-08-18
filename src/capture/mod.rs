use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub mod file;
pub mod live;
pub mod replay;
pub mod stdin;

/// Unified capture source: pull-based, zero-copy.
///
/// Packet bytes are borrowed from the pcap ring for the duration of `f` only.
pub trait CaptureSource: Send {
    /// Invoke `f` with `(ts_us, linktype, packet_bytes)` for the next frame.
    /// Returns `false` on EOF or shutdown.
    fn next_frame(&mut self, f: &mut dyn FnMut(u64, u32, &[u8])) -> bool;

    /// Attach a pipeline shutdown signal. Once set, `next_frame` must return
    /// `false` promptly so the pipeline can drain and exit cleanly.
    fn set_stop(&mut self, _stop: Arc<AtomicBool>) {}
}

impl CaptureSource for Box<dyn CaptureSource> {
    fn next_frame(&mut self, f: &mut dyn FnMut(u64, u32, &[u8])) -> bool {
        (**self).next_frame(f)
    }
    fn set_stop(&mut self, stop: Arc<AtomicBool>) {
        (**self).set_stop(stop)
    }
}

pub(crate) fn pcap_ts_us(header: &pcap::PacketHeader) -> u64 {
    header.ts.tv_sec as u64 * 1_000_000 + header.ts.tv_usec as u64
}

/// Sleep in bounded slices, returning `false` (early) when `stop` flips set.
pub fn sleep_interruptible(d: Duration, stop: &AtomicBool) -> bool {
    const CHUNK: Duration = Duration::from_millis(50);
    let mut left = d;
    while left > CHUNK {
        std::thread::sleep(CHUNK);
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        left -= CHUNK;
    }
    std::thread::sleep(left);
    !stop.load(std::sync::atomic::Ordering::Relaxed)
}
