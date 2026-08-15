use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytes::Bytes;

pub mod file;
pub mod live;
pub mod replay;
pub mod stdin;

/// One raw captured frame, before L3/L4 decoding.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub ts_us: u64,
    pub linktype: u32,
    pub data: Bytes,
}

/// Unified capture source: a pull-based iterator of raw frames.
pub trait CaptureSource: Send {
    fn next_frame(&mut self) -> Option<RawFrame>;

    /// Attach a pipeline shutdown signal. Once set, `next_frame` must return
    /// `None` promptly so the pipeline can drain and exit cleanly.
    fn set_stop(&mut self, _stop: Arc<AtomicBool>) {}
}

impl CaptureSource for Box<dyn CaptureSource> {
    fn next_frame(&mut self) -> Option<RawFrame> {
        (**self).next_frame()
    }
    fn set_stop(&mut self, stop: Arc<AtomicBool>) {
        (**self).set_stop(stop)
    }
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
