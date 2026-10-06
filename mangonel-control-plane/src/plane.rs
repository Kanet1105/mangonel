//! The control-plane thread and the handles that talk to
//! it.
//!
//! One dedicated thread owns the left-right
//! [`WriteHandle`]. Users never touch it: they send
//! requests down a queue through a [`ControlHandle`], and
//! the thread validates, applies and publishes each one in
//! order. Readers — typically data-plane threads — hold a
//! [`Reader`] and see the last published [`State`] without
//! taking a lock.

use std::{
    io,
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, JoinHandle},
};

use left_right::{ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use thiserror::Error;

use crate::{Acl, AclEntry, ConfigError, Direction, LanPort, MacAddr, State, WanPort, state::Op};

/// Owner of the control-plane thread.
///
/// Dropping it stops the thread after the requests already
/// queued are handled, and waits for it to exit. From then
/// on [`ControlHandle`] calls return [`Error::Stopped`] and
/// [`Reader::enter`] returns `None`.
pub struct ControlPlane {
    requests: Sender<Request>,
    readers: ReadHandleFactory<State>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        // The thread only exits on Shutdown, so it cannot
        // have hung up yet.
        let _ = self.requests.send(Request::Shutdown);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
            && !thread::panicking()
        {
            panic!("control-plane thread panicked");
        }
    }
}

impl ControlPlane {
    /// Starts the thread with no ports configured.
    pub fn spawn() -> io::Result<Self> {
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

    /// A handle for submitting changes. Clone it freely.
    pub fn handle(&self) -> ControlHandle {
        ControlHandle {
            requests: self.requests.clone(),
        }
    }

    /// A reader for one thread.
    pub fn reader(&self) -> Reader {
        Reader(self.readers.handle())
    }
}

/// Submits changes to the control plane.
///
/// Each call blocks until the thread has handled the
/// request. On `Ok`, the change is already published: every
/// [`Reader::enter`] from then on sees it.
#[derive(Clone)]
pub struct ControlHandle {
    requests: Sender<Request>,
}

impl ControlHandle {
    /// Adds a WAN port, or replaces the one with the same
    /// MAC.
    pub fn set_wan(&self, port: WanPort) -> Result<(), Error> {
        self.request(Op::SetWan(port))
    }

    /// Adds a LAN port, or replaces the one with the same
    /// MAC.
    pub fn set_lan(&self, port: LanPort) -> Result<(), Error> {
        self.request(Op::SetLan(port))
    }

    pub fn remove_wan(&self, mac: MacAddr) -> Result<(), Error> {
        self.request(Op::RemoveWan(mac))
    }

    pub fn remove_lan(&self, mac: MacAddr) -> Result<(), Error> {
        self.request(Op::RemoveLan(mac))
    }

    /// Creates an ACL, or replaces the one with the same
    /// name along with all its entries.
    pub fn set_acl(&self, acl: Acl) -> Result<(), Error> {
        self.request(Op::SetAcl(acl))
    }

    /// Fails with [`ConfigError::AclInUse`] while the ACL
    /// is attached to a port.
    pub fn remove_acl(&self, name: &str) -> Result<(), Error> {
        self.request(Op::RemoveAcl(name.to_owned()))
    }

    /// Adds an entry to the ACL `name`, or replaces the one
    /// with the same sequence number.
    pub fn set_acl_entry(&self, name: &str, entry: AclEntry) -> Result<(), Error> {
        self.request(Op::SetAclEntry(name.to_owned(), entry))
    }

    pub fn remove_acl_entry(&self, name: &str, seq: u32) -> Result<(), Error> {
        self.request(Op::RemoveAclEntry(name.to_owned(), seq))
    }

    /// Attaches the ACL `name` to `direction` on the WAN or
    /// LAN port `mac`, replacing whatever was attached
    /// there.
    pub fn attach_acl(&self, mac: MacAddr, direction: Direction, name: &str) -> Result<(), Error> {
        self.request(Op::SetPortAcl(mac, direction, Some(name.to_owned())))
    }

    /// Detaches whatever ACL filters `direction` on port
    /// `mac`. Not an error if none is attached.
    pub fn detach_acl(&self, mac: MacAddr, direction: Direction) -> Result<(), Error> {
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
/// [`ControlPlane::reader`] or [`Clone`].
#[derive(Clone)]
pub struct Reader(ReadHandle<State>);

impl Reader {
    /// The current state, or `None` once the control plane
    /// has stopped.
    ///
    /// Keep the guard short-lived: the control plane cannot
    /// finish publishing a change while any reader still
    /// holds the copy it is about to overwrite.
    pub fn enter(&self) -> Option<ReadGuard<'_, State>> {
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
pub enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("control plane has stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        acl::tests::permit_web,
        port::tests::{LAN_MAC, WAN_MAC, lan, wan_static},
    };

    #[test]
    fn changes_are_visible_once_acknowledged() {
        let plane = ControlPlane::spawn().unwrap();
        let handle = plane.handle();
        let reader = plane.reader();

        handle
            .set_wan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1"))
            .unwrap();
        handle
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();
        {
            let state = reader.enter().unwrap();
            assert_eq!(state.wan_ports().len(), 1);
            assert_eq!(state.lan_ports().len(), 1);
        }

        handle.remove_wan(WAN_MAC).unwrap();
        assert!(reader.enter().unwrap().wan(WAN_MAC).is_none());
    }

    #[test]
    fn rejected_changes_leave_state_untouched() {
        let plane = ControlPlane::spawn().unwrap();
        let handle = plane.handle();

        assert_eq!(
            handle.remove_lan(LAN_MAC),
            Err(Error::Config(ConfigError::NotFound(
                LAN_MAC,
                crate::Role::Lan
            )))
        );
        assert!(plane.reader().enter().unwrap().lan_ports().is_empty());
    }

    #[test]
    fn readers_work_from_other_threads() {
        let plane = ControlPlane::spawn().unwrap();
        plane
            .handle()
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();

        let reader = plane.reader();
        let seen = thread::spawn(move || reader.enter().unwrap().lan_ports().len())
            .join()
            .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn handles_fail_after_shutdown() {
        let plane = ControlPlane::spawn().unwrap();
        let handle = plane.handle();
        let reader = plane.reader();
        drop(plane);

        assert_eq!(handle.remove_wan(WAN_MAC), Err(Error::Stopped));
        assert!(reader.enter().is_none());
    }

    #[test]
    fn acl_crud() {
        let plane = ControlPlane::spawn().unwrap();
        let handle = plane.handle();
        let reader = plane.reader();

        handle.set_acl(Acl::new("lan-in")).unwrap();
        handle.set_acl_entry("lan-in", permit_web(10)).unwrap();
        assert_eq!(
            reader.enter().unwrap().acl("lan-in").unwrap().entry(10),
            Some(&permit_web(10))
        );

        handle.remove_acl_entry("lan-in", 10).unwrap();
        assert!(
            reader
                .enter()
                .unwrap()
                .acl("lan-in")
                .unwrap()
                .entries
                .is_empty()
        );

        handle.remove_acl("lan-in").unwrap();
        assert_eq!(
            handle.set_acl_entry("lan-in", permit_web(10)),
            Err(Error::Config(ConfigError::AclNotFound("lan-in".to_owned())))
        );
    }

    #[test]
    fn attach_and_detach() {
        let plane = ControlPlane::spawn().unwrap();
        let handle = plane.handle();
        let reader = plane.reader();

        handle.set_acl(Acl::new("lan-in")).unwrap();
        handle
            .set_lan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))
            .unwrap();
        handle
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
            handle.remove_acl("lan-in"),
            Err(Error::Config(ConfigError::AclInUse(
                "lan-in".to_owned(),
                LAN_MAC
            )))
        );

        handle.detach_acl(LAN_MAC, Direction::Inbound).unwrap();
        handle.remove_acl("lan-in").unwrap();
    }
}
