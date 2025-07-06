use crate::{
    interface::{get_network_interface, NetworkInterfaceError},
    payload::Payload,
    socket::{SocketRx, SocketTx},
};
use mangonel_thread::{spawn, ThreadError};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Sender, TryRecvError},
        Arc,
    },
    thread::JoinHandle,
};

#[derive(Default)]
pub struct Runtime;

impl Runtime {
    pub fn run(self, nic: &str, worker_count: usize) -> Result<(), RuntimeError> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        // Setup the network interface.
        let nic = get_network_interface(&nic)?;
        tracing::info!("Using network interface: {}", nic.name);

        // Setup the flag.
        let flag = Flag::default();

        // Create a socket.

        // Initialize the Rx socket.
        // Initialize the Tx socket.
        // Intialize the workers.
        Ok(())
    }
}

pub struct Flag(Arc<AtomicBool>);

impl Clone for Flag {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Default for Flag {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Flag {
    pub fn is_running(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

// struct Worker {
//     sender: Sender<EmptyPayload>,
// }

// impl Worker {
//     pub fn run(
//         core_id: usize,
//         flag: Flag,
//         tx_queue: Sender<EmptyPayload>,
//     ) -> Result<(Self, JoinHandle<Result<(), RuntimeError>>), RuntimeError> {
//         let (sender, receiver) = channel();
//         let handle = spawn(core_id, move || {
//             while flag.is_running() {
//                 match receiver.try_recv() {
//                     Ok(packet) => tx_queue.send(packet).unwrap(),
//                     Err(TryRecvError::Empty) => {}
//                     Err(TryRecvError::Disconnected) => return Err(RuntimeError::SenderDropped),
//                 }
//             }
//             Ok(())
//         })?;
//         let worker = Self { sender };
//         Ok((worker, handle))
//     }
// }

// #[derive(Clone)]
// pub struct TxWorker {
//     sender: Sender<EmptyPayload>,
// }

// impl TxWorker {
//     pub fn run(
//         core_id: usize,
//         flag: Flag,
//         mut tx_socket: impl TxSocket,
//     ) -> Result<(Self, JoinHandle<()>), RuntimeError> {
//         let (sender, receiver) = channel();
//         let handle = spawn(core_id, move || {
//             while flag.is_running() {
//                 tx_socket.write_iter(receiver.try_iter());
//             }
//         })?;
//         let tx_worker = Self { sender };
//         Ok((tx_worker, handle))
//     }
// }

// pub struct RxWorker;

// impl RxWorker {
//     pub fn run(
//         core_id: usize,
//         flag: Flag,
//         mut rx_socket: impl RxSocket,
//         sender: Vec<Sender<EmptyPayload>>,
//     ) -> Result<(Self, JoinHandle<()>), RuntimeError> {
//         let handle = spawn(core_id, move || {
//             while flag.is_running() {
//                 for packet in rx_socket.read_iter() {
//                     packet.target_cpu();
//                 }
//             }
//         })?;
//         let rx_worker = Self;
//         Ok((rx_worker, handle))
//     }
// }

pub enum RuntimeError {
    AvailableCore(std::io::Error),
    NotEnoughCores(usize, usize),
    InterfaceError(NetworkInterfaceError),
    ThreadError(ThreadError),
    SenderDropped,
}

impl std::fmt::Debug for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AvailableCore(error) => {
                write!(f, "Failed to get available cores: {}", error)
            }
            Self::NotEnoughCores(available, required) => {
                write!(
                    f,
                    "Not enough cores available: {} available, {} required",
                    available, required
                )
            }
            Self::InterfaceError(error) => {
                write!(f, "Network interface error: {}", error)
            }
            Self::ThreadError(error) => {
                write!(f, "Thread error: {}", error)
            }
            Self::SenderDropped => {
                write!(f, "Sender dropped")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<NetworkInterfaceError> for RuntimeError {
    fn from(value: NetworkInterfaceError) -> Self {
        Self::InterfaceError(value)
    }
}

impl From<ThreadError> for RuntimeError {
    fn from(value: ThreadError) -> Self {
        Self::ThreadError(value)
    }
}
