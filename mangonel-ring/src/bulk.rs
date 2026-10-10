use crate::Ring;

pub struct BulkWrite<'a, T> {
    ring: &'a Ring<T>,
    size: usize,
    cached: usize,
    current: usize,
}

impl<'a, T> Drop for BulkWrite<'a, T> {
    fn drop(&mut self) {
        self.ring.commit_write(self.size, self.cached);
    }
}

impl<'a, T> Iterator for BulkWrite<'a, T> {
    type Item = &'a mut Option<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.cached.wrapping_add(self.size) {
            None
        } else {
            // SAFETY: the claim gives this grant the slot alone
            // until commit, and `current` yields each slot once.
            let item = unsafe { &mut *self.ring.slot(self.current) };
            self.current = self.current.wrapping_add(1);

            Some(item)
        }
    }
}

impl<'a, T> BulkWrite<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            size: n,
            cached: index,
            current: index,
        }
    }
}

pub struct BulkRead<'a, T> {
    ring: &'a Ring<T>,
    size: usize,
    cached: usize,
    current: usize,
}

impl<'a, T> Drop for BulkRead<'a, T> {
    fn drop(&mut self) {
        // A value left unread would pass for a write next lap.
        let end = self.cached.wrapping_add(self.size);
        while self.current != end {
            // SAFETY: the claim keeps producers off the slot
            // until commit.
            unsafe { *self.ring.slot(self.current) = None };
            self.current = self.current.wrapping_add(1);
        }
        self.ring.commit_read(self.size, self.cached)
    }
}

impl<'a, T> Iterator for BulkRead<'a, T> {
    type Item = T;

    /// `None` also for a slot left unwritten.
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.cached.wrapping_add(self.size) {
            None
        } else {
            // SAFETY: the claim keeps producers off the slot
            // until commit.
            let item = unsafe { (*self.ring.slot(self.current)).take() };
            self.current = self.current.wrapping_add(1);

            item
        }
    }
}

impl<'a, T> BulkRead<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            size: n,
            cached: index,
            current: index,
        }
    }
}
