use crate::{Error, Ring};

/// Free slots claimed by [`Ring::bulk_write`]; iterating
/// `&mut` it yields each once for writing. Dropping it
/// publishes them all; a slot left `None` reads as a gap.
#[must_use = "dropping the grant commits it"]
pub struct BulkWrite<'a, T> {
    ring: &'a Ring<T>,
    size: usize,
    start: usize,
    current: usize,
    end: usize,
}

impl<'a, T> Drop for BulkWrite<'a, T> {
    fn drop(&mut self) {
        self.ring.commit_write(self);
    }
}

impl<'a, T> BulkWrite<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            size: n,
            start: index,
            current: index,
            end: index.wrapping_add(n),
        }
    }

    pub(crate) fn index(&self) -> usize {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size
    }

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
    size: usize,
    start: usize,
    current: usize,
    end: usize,
}

impl<'a, T> Drop for BulkRead<'a, T> {
    fn drop(&mut self) {
        self.ring.commit_read(self)
    }
}

impl<'a, T> BulkRead<'a, T> {
    pub(crate) fn new(ring: &'a Ring<T>, n: usize, index: usize) -> Self {
        Self {
            ring,
            size: n,
            start: index,
            current: index,
            end: index.wrapping_add(n),
        }
    }

    pub(crate) fn index(&self) -> usize {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size
    }

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
