//! The control-panel thread and the handles that talk to
//! it.
//!
//! One dedicated thread owns the left-right
//! [`WriteHandle`]. Users never touch it: they send
//! requests down a queue through [`ControlPanel`]'s
//! methods, and the thread validates, applies and publishes
//! each one in order. Readers — typically data-plane
//! threads — hold a [`Reader`] and see the last published
//! [`State`] without taking a lock.

use std::{
    io,
    sync::mpsc::{
        self,
        Receiver,
        Sender,
    },
    thread::{
        self,
        JoinHandle,
    },
};

use left_right::{
    ReadGuard,
    ReadHandle,
    ReadHandleFactory,
    WriteHandle,
};
use thiserror::Error;

use crate::control::{
    Acl,
    AclEntry,
    ConfigError,
    Direction,
    LanPort,
    MacAddr,
    State,
    WanPort,
    state::Op,
};

/// Owner of the control-panel thread, and the way to change
/// its state. Share it by reference or `Arc` to submit
/// changes from several threads.
///
/// Each change blocks until the thread has handled it. On
/// `Ok`, the change is already published: every
/// [`Reader::enter`] from then on sees it.
///
/// Dropping it stops the thread after the requests already
/// queued are handled, and waits for it to exit. From then
/// on [`Reader::enter`] returns `None`.
pub(crate) struct ControlPanel {
    requests: Sender<Request>,
    readers: ReadHandleFactory<State>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ControlPanel {
    fn drop(&mut self) {
        // The thread only exits on Shutdown, so it cannot
        // have hung up yet.
        let _ = self.requests.send(Request::Shutdown);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
            && !thread::panicking()
        {
            panic!("control-panel thread panicked");
        }
    }
}

impl ControlPanel {
    /// Starts the thread with no ports configured.
    pub(crate) fn spawn() -> io::Result<Self> {
        let (writer, reader) = left_right::new::<State, Op>();
        let (requests, queue) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("mangonel-control".to_owned())
            .spawn(move || run(writer, queue))?;
        Ok(Self {
            requests,
            readers: reader.factory(),
            thread: Some(thread),
        })
    }

    /// A reader for one thread.
    pub(crate) fn reader(&self) -> Reader {
        Reader(self.readers.handle())
    }

    /// Adds a WAN port, or replaces the one with the same
    /// MAC.
    pub(crate) fn set_wan(&self, port: WanPort) -> Result<(), Error> {
        self.request(Op::SetWan(port))
    }

    /// Adds a LAN port, or replaces the one with the same
    /// MAC.
    pub(crate) fn set_lan(&self, port: LanPort) -> Result<(), Error> {
        self.request(Op::SetLan(port))
    }

    pub(crate) fn remove_wan(&self, mac: MacAddr) -> Result<(), Error> {
        self.request(Op::RemoveWan(mac))
    }

    pub(crate) fn remove_lan(&self, mac: MacAddr) -> Result<(), Error> {
        self.request(Op::RemoveLan(mac))
    }

    /// Creates an ACL, or replaces the one with the same
    /// name along with all its entries.
    pub(crate) fn set_acl(&self, acl: Acl) -> Result<(), Error> {
        self.request(Op::SetAcl(acl))
    }

    /// Fails with [`ConfigError::AclInUse`] while the ACL
    /// is attached to a port.
    pub(crate) fn remove_acl(&self, name: &str) -> Result<(), Error> {
        self.request(Op::RemoveAcl(name.to_owned()))
    }

    /// Adds an entry to the ACL `name`, or replaces the one
    /// with the same sequence number.
    pub(crate) fn set_acl_entry(&self, name: &str, entry: AclEntry) -> Result<(), Error> {
        self.request(Op::SetAclEntry(name.to_owned(), entry))
    }

    pub(crate) fn remove_acl_entry(&self, name: &str, seq: u32) -> Result<(), Error> {
        self.request(Op::RemoveAclEntry(name.to_owned(), seq))
    }

    /// Attaches the ACL `name` to `direction` on the WAN or
    /// LAN port `mac`, replacing whatever was attached
    /// there.
    pub(crate) fn attach_acl(
        &self,
        mac: MacAddr,
        direction: Direction,
        name: &str,
    ) -> Result<(), Error> {
        self.request(Op::SetPortAcl(mac, direction, Some(name.to_owned())))
    }

    /// Detaches whatever ACL filters `direction` on port
    /// `mac`. Not an error if none is attached.
    pub(crate) fn detach_acl(&self, mac: MacAddr, direction: Direction) -> Result<(), Error> {
        self.request(Op::SetPortAcl(mac, direction, None))
    }

    fn request(&self, op: Op) -> Result<(), Error> {
        let (reply, response) = mpsc::channel();
        self.requests
            .send(Request::Apply(op, reply))
            .map_err(|_| Error::Stopped)?;
        Ok(response.recv().map_err(|_| Error::Stopped)??)
    }
}

/// Lock-free read access to the published [`State`].
///
/// `Send` but not `Sync`: give each thread its own, via
/// [`ControlPanel::reader`] or [`Clone`].
#[derive(Clone)]
pub(crate) struct Reader(ReadHandle<State>);

impl Reader {
    /// The current state, or `None` once the control panel
    /// has stopped.
    ///
    /// Keep the guard short-lived: the control panel cannot
    /// finish publishing a change while any reader still
    /// holds the copy it is about to overwrite.
    pub(crate) fn enter(&self) -> Option<ReadGuard<'_, State>> {
        self.0.enter()
    }
}

enum Request {
    Apply(Op, Sender<Result<(), ConfigError>>),
    Shutdown,
}

fn run(mut writer: WriteHandle<State, Op>, queue: Receiver<Request>) {
    // Publishing after every op keeps the published copy
    // current, so it is what the next op is checked
    // against.
    for request in queue {
        match request {
            Request::Apply(op, reply) => {
                let result = writer
                    .enter()
                    .expect("the writer outlives its own read handle")
                    .check(&op);
                if result.is_ok() {
                    writer.append(op).publish();
                }
                // The requester may have given up waiting.
                let _ = reply.send(result);
            }
            Request::Shutdown => break,
        }
    }
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("control panel has stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{
        acl::tests::permit_web,
        port::tests::{
            LAN_MAC,
            WAN_MAC,
            lan,
            wan_static,
        },
    };

    #[test]
    fn changes_are_visible_once_acknowledged() {
        let plane = ControlPanel::spawn().unwrap();
        let reader = plane.reader();

        plane
            .set_wan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1"))
            .unwrap();
        plane
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();
        {
            let state = reader.enter().unwrap();
            assert_eq!(state.wan_ports().len(), 1);
            assert_eq!(state.lan_ports().len(), 1);
        }

        plane.remove_wan(WAN_MAC).unwrap();
        assert!(reader.enter().unwrap().wan(WAN_MAC).is_none());
    }

    #[test]
    fn rejected_changes_leave_state_untouched() {
        let plane = ControlPanel::spawn().unwrap();

        assert_eq!(
            plane.remove_lan(LAN_MAC),
            Err(Error::Config(ConfigError::NotFound(
                LAN_MAC,
                crate::control::Role::Lan
            )))
        );
        assert!(plane.reader().enter().unwrap().lan_ports().is_empty());
    }

    #[test]
    fn readers_work_from_other_threads() {
        let plane = ControlPanel::spawn().unwrap();
        plane
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();

        let reader = plane.reader();
        let seen = thread::spawn(move || reader.enter().unwrap().lan_ports().len())
            .join()
            .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn readers_see_nothing_after_shutdown() {
        let plane = ControlPanel::spawn().unwrap();
        let reader = plane.reader();
        drop(plane);

        assert!(reader.enter().is_none());
    }

    #[test]
    fn acl_crud() {
        let plane = ControlPanel::spawn().unwrap();
        let reader = plane.reader();

        plane.set_acl(Acl::new("lan-in")).unwrap();
        plane.set_acl_entry("lan-in", permit_web(10)).unwrap();
        assert_eq!(
            reader.enter().unwrap().acl("lan-in").unwrap().entry(10),
            Some(&permit_web(10))
        );

        plane.remove_acl_entry("lan-in", 10).unwrap();
        assert!(
            reader
                .enter()
                .unwrap()
                .acl("lan-in")
                .unwrap()
                .entries
                .is_empty()
        );

        plane.remove_acl("lan-in").unwrap();
        assert_eq!(
            plane.set_acl_entry("lan-in", permit_web(10)),
            Err(Error::Config(ConfigError::AclNotFound("lan-in".to_owned())))
        );
    }

    #[test]
    fn attach_and_detach() {
        let plane = ControlPanel::spawn().unwrap();
        let reader = plane.reader();

        plane.set_acl(Acl::new("lan-in")).unwrap();
        plane
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();
        plane
            .attach_acl(LAN_MAC, Direction::Inbound, "lan-in")
            .unwrap();
        assert!(
            reader
                .enter()
                .unwrap()
                .port_acl(LAN_MAC, Direction::Inbound)
                .is_some()
        );
        assert_eq!(
            plane.remove_acl("lan-in"),
            Err(Error::Config(ConfigError::AclInUse(
                "lan-in".to_owned(),
                LAN_MAC
            )))
        );

        plane.detach_acl(LAN_MAC, Direction::Inbound).unwrap();
        plane.remove_acl("lan-in").unwrap();
    }
}
