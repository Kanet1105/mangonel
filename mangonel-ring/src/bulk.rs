use std::fmt;

use crate::{Error, Ring};

/// Free slots claimed by [`Ring::bulk_write`], filled in
/// order by [`write`](Self::write). Dropping it publishes
/// them all; readers skip a slot left unwritten.
#[must_use = "dropping the grant commits it"]
pub struct BulkWrite<'a, T> {
    ring: &'a Ring<T>,
    start: usize,
    current: usize,
    end: usize,
}

impl<'a, T> Drop for BulkWrite<'a, T> {
    fn drop(&mut self) {
        self.ring.commit_write(self);
    }
}

impl<'a, T> fmt::Debug for BulkWrite<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkWrite")
            .field("start", &self.start)
            .field("current", &self.current)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

impl<'a, T> BulkWrite<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            start: index,
            current: index,
            end: index.wrapping_add(n),
        }
    }

    pub(crate) fn start(&self) -> usize {
        self.start
    }

    pub(crate) fn end(&self) -> usize {
        self.end
    }

    /// Slots claimed, at most the `n` asked for.
    pub fn size(&self) -> usize {
        self.end.wrapping_sub(self.start)
    }

    /// Writes `value` into the next free slot.
    ///
    /// # Errors
    ///
    /// [`Error::GrantIsFull`] if every slot is written.
    pub fn write(&mut self, value: T) -> Result<(), Error> {
        if self.current == self.end {
            return Err(Error::GrantIsFull);
        }

        let index = self.current;
        self.current = self.current.wrapping_add(1);
        // SAFETY: the claim gives this grant the slot alone
        // until commit.
        let item = unsafe { &mut *self.ring.slot(index) };
        *item = Some(value);

        Ok(())
    }
}

/// Published slots claimed by [`Ring::bulk_read`], yielded
/// once each as owned values. Dropping it frees them all,
/// dropping any value left unread.
#[must_use = "dropping the grant commits it"]
pub struct BulkRead<'a, T> {
    ring: &'a Ring<T>,
    start: usize,
    current: usize,
    end: usize,
}

impl<'a, T> Drop for BulkRead<'a, T> {
    fn drop(&mut self) {
        self.ring.commit_read(self)
    }
}

impl<'a, T> fmt::Debug for BulkRead<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkRead")
            .field("start", &self.start)
            .field("current", &self.current)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

impl<'a, T> BulkRead<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            start: index,
            current: index,
            end: index.wrapping_add(n),
        }
    }

    pub(crate) fn start(&self) -> usize {
        self.start
    }

    pub(crate) fn current(&self) -> usize {
        self.current
    }

    pub(crate) fn end(&self) -> usize {
        self.end
    }

    /// Slots claimed, gaps included, at most the `n`
    /// asked for.
    pub fn size(&self) -> usize {
        self.end.wrapping_sub(self.start)
    }

    /// Takes the next value, skipping gaps, or `None`
    /// once every slot is read.
    pub fn read(&mut self) -> Option<T> {
        while self.current != self.end {
            let index = self.current;
            self.current = self.current.wrapping_add(1);
            // SAFETY: the claim keeps producers off the slot
            // until commit.
            let item = unsafe { &mut *self.ring.slot(index) };
            // A gap is a slot left unwritten; skip it.
            if let Some(value) = item.take() {
                return Some(value);
            }
        }

        None
    }
}
