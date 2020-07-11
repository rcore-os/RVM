//! Some structures about virtual interrupts.

use bit_set::BitSet;

/// The virtual interrupt controller to track pending interrupts
#[derive(Debug)]
pub struct InterruptController {
    max_num: usize,
    bitset: BitSet,
}

impl InterruptController {
    pub fn new(max_num: usize) -> Self {
        Self {
            max_num,
            bitset: BitSet::with_capacity(max_num + 1),
        }
    }

    // In some architecture need to reverse the interrupt priority.
    #[inline(always)]
    fn vector(&self, vec: usize) -> usize {
        self.max_num - vec
    }

    /// Try to pop an interrupt with the given vector.
    pub fn try_pop(&mut self, vec: usize) -> bool {
        self.bitset.remove(self.vector(vec))
    }

    /// Pops the highest priority interrupt.
    pub fn pop(&mut self) -> Option<usize> {
        self.bitset.iter().next().map(|vec| {
            self.bitset.remove(vec);
            self.vector(vec)
        })
    }

    /// Clears all vectors except the given vector.
    pub fn clear_and_keep(&mut self, vec: usize) {
        let vec = self.vector(vec);
        let has = self.bitset.contains(vec);
        self.bitset.clear();
        if has {
            self.bitset.insert(vec);
        }
    }

    /// Tracks the given interrupt.
    pub fn virtual_interrupt(&mut self, vec: usize) {
        self.bitset.insert(self.vector(vec));
    }
}

/// A virtual timer to issue virtual time IRQ.
#[derive(Debug, Default)]
pub struct VirtualTimer {
    current: usize,
    count: usize,
    enabled: bool,
}

impl VirtualTimer {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enable(&mut self, enable: bool) {
        self.current = 0;
        self.enabled = enable;
    }

    pub fn set_count(&mut self, count: usize) {
        if count > 0 {
            self.count = count;
        }
    }

    pub fn tick(&mut self) -> bool {
        self.current += 1;
        if self.current >= self.count {
            self.current -= self.count;
            true
        } else {
            false
        }
    }
}
