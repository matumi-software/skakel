//! When the media source sends a frame and which one: a fixed grid of sample times, and the choice
//! between the producer's frame and the idle frame. Pure arithmetic, so it is tested without a clock.

/// 100 ns units in a second, the unit of Media Foundation sample times.
pub const UNITS_PER_SECOND: u64 = 10_000_000;

/// One slot on the grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick {
    /// Which slot, counted from the start.
    pub index: u64,
    /// The sample time, in 100 ns units on the clock the grid started on.
    pub time: i64,
    /// Until the next slot's time.
    pub duration: i64,
}

/// A grid of sample times at the camera's rate, from a start time. Each slot is sent at most once;
/// when the source wakes late it sends the slot it is in and skips the ones it missed, so sample
/// times always step by whole frames and never bunch up.
#[derive(Clone, Debug)]
pub struct Pacer {
    start: i64,
    fps_num: u64,
    fps_den: u64,
    last: Option<u64>,
}

impl Pacer {
    pub fn new(start: i64, fps_num: u32, fps_den: u32) -> Self {
        assert!(fps_num > 0 && fps_den > 0);
        Self {
            start,
            fps_num: fps_num.into(),
            fps_den: fps_den.into(),
            last: None,
        }
    }

    /// The time of slot `index`, computed from the start each time so it never drifts.
    pub fn time_of(&self, index: u64) -> i64 {
        let offset = u128::from(index) * u128::from(UNITS_PER_SECOND) * u128::from(self.fps_den)
            / u128::from(self.fps_num);
        self.start + offset as i64
    }

    /// The slot `now` falls in.
    fn index_at(&self, now: i64) -> u64 {
        if now <= self.start {
            return 0;
        }
        let elapsed = (now - self.start) as u128;
        (elapsed * u128::from(self.fps_num)
            / (u128::from(UNITS_PER_SECOND) * u128::from(self.fps_den))) as u64
    }

    /// The slot to send at `now`, or None when the slot `now` falls in was sent already.
    pub fn poll(&mut self, now: i64) -> Option<Tick> {
        let index = self.index_at(now);
        if self.last.is_some_and(|last| index <= last) {
            return None;
        }
        self.last = Some(index);
        let time = self.time_of(index);
        Some(Tick {
            index,
            time,
            duration: self.time_of(index + 1) - time,
        })
    }

    /// When the next slot starts.
    pub fn next_due(&self) -> i64 {
        self.time_of(self.last.map_or(0, |last| last + 1))
    }
}

/// What the source shows on a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Show {
    /// The producer's latest frame, new or repeated.
    Frame,
    /// The idle frame.
    Idle,
}

/// The producer's frame while it is attached and its latest frame is no older than the timeout,
/// the idle frame otherwise. Times are in milliseconds on any one clock.
pub fn choose(
    producer_attached: bool,
    last_new_frame_ms: Option<u64>,
    now_ms: u64,
    idle_timeout_ms: u32,
) -> Show {
    match last_new_frame_ms {
        Some(at)
            if producer_attached && now_ms.saturating_sub(at) <= u64::from(idle_timeout_ms) =>
        {
            Show::Frame
        }
        _ => Show::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: i64 = 5_000_000_000;

    #[test]
    fn steps_by_whole_frames_at_30_fps() {
        let mut pacer = Pacer::new(START, 30, 1);
        let first = pacer.poll(START).unwrap();
        assert_eq!(
            first,
            Tick {
                index: 0,
                time: START,
                duration: 333_333
            }
        );
        assert_eq!(pacer.poll(START + 100_000), None);
        let second = pacer.poll(START + 333_400).unwrap();
        assert_eq!((second.index, second.time), (1, START + 333_333));
        assert_eq!(pacer.next_due(), START + 666_666);
    }

    #[test]
    fn three_seconds_add_up_exactly() {
        let pacer = Pacer::new(START, 30, 1);
        assert_eq!(pacer.time_of(90), START + 30_000_000);
        let ntsc = Pacer::new(0, 30_000, 1001);
        assert_eq!(ntsc.time_of(30_000), 1001 * 10_000_000);
    }

    #[test]
    fn durations_fill_the_grid_without_gaps() {
        let mut pacer = Pacer::new(START, 30, 1);
        let mut expected = START;
        for index in 0..300 {
            let tick = pacer.poll(pacer.time_of(index) + 10).unwrap();
            assert_eq!(tick.time, expected);
            expected += tick.duration;
        }
        assert_eq!(expected, START + 100_000_000);
    }

    #[test]
    fn a_late_wake_skips_the_missed_slots() {
        let mut pacer = Pacer::new(START, 30, 1);
        pacer.poll(START).unwrap();
        // Woke 100 ms late: slots 1 and 2 are gone, slot 3 is sent with its own time.
        let tick = pacer.poll(START + 1_000_000 + 50).unwrap();
        assert_eq!((tick.index, tick.time), (3, START + 1_000_000));
        assert_eq!(pacer.poll(START + 1_000_100), None);
    }

    #[test]
    fn before_the_start_is_slot_zero() {
        let mut pacer = Pacer::new(START, 60, 1);
        assert_eq!(pacer.poll(START - 10).unwrap().index, 0);
        assert_eq!(pacer.next_due(), START + 166_666);
    }

    #[test]
    fn shows_the_frame_while_it_is_fresh() {
        assert_eq!(choose(true, Some(1000), 1500, 2000), Show::Frame);
        assert_eq!(choose(true, Some(1000), 3000, 2000), Show::Frame);
        assert_eq!(choose(true, Some(1000), 3001, 2000), Show::Idle);
    }

    #[test]
    fn shows_idle_without_a_frame_or_a_producer() {
        assert_eq!(choose(true, None, 0, 2000), Show::Idle);
        assert_eq!(choose(false, Some(1000), 1001, 2000), Show::Idle);
    }

    #[test]
    fn frames_return_after_idle() {
        assert_eq!(choose(true, Some(0), 10_000, 2000), Show::Idle);
        assert_eq!(choose(true, Some(10_000), 10_010, 2000), Show::Frame);
    }
}
