//! x86 virtual timer

use super::consts::*;
use crate::interrupt::VirtualTimer;

#[derive(Debug)]
enum PitTimerRwState {
    Lsb,
    Msb,
}
use PitTimerRwState::*;

/// Virtual Programmalbe Interval Timer
#[derive(Debug)]
pub struct PitTimer {
    read_state: PitTimerRwState,
    write_state: PitTimerRwState,
    count: usize,
    pub inner: VirtualTimer,
}

impl PitTimer {
    const FREQ: usize = 1193182;
    pub const IRQ_NUM: u8 = IRQ0 + Timer;

    fn count_to_us(&self) -> usize {
        (self.count as u64 * 1_000_000u64 / Self::FREQ as u64) as usize
    }

    pub fn read(&mut self) -> u8 {
        match self.read_state {
            Lsb => {
                self.read_state = Msb;
                (self.count & 0xff) as u8
            }
            Msb => {
                self.read_state = Lsb;
                (self.count >> 8) as u8
            }
        }
    }

    pub fn write(&mut self, value: u8) {
        match self.write_state {
            Lsb => {
                self.count = value as usize;
                self.write_state = Msb;
            }
            Msb => {
                self.count |= (value as usize) << 8;
                self.write_state = Lsb;
                self.inner
                    .set_count(self.count_to_us() / super::consts::USEC_PER_TICK);
                self.inner.set_enable(true);
            }
        }
    }
}

impl Default for PitTimer {
    fn default() -> Self {
        let inner = VirtualTimer::default();
        Self {
            read_state: Lsb,
            write_state: Lsb,
            count: 0,
            inner,
        }
    }
}
