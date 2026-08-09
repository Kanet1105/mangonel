//! The mangonel control daemon: an HTTP+JSON API over a
//! Unix socket, dispatching to [`State`].

use std::{
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    sync::Arc,
    time::Instant,
};

use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mangonel::{
    api,
    state::{State, StateError},
};
use tokio::{net::UnixListener, signal, sync::Notify};

/// Everything the handlers share. Cheap to clone — the
/// state and the shutdown notifier are behind `Arc`.
#[derive(Clone)]
struct App {
    state: Arc<State>,
    shutdown: Arc<Notify>,
    start: Instant,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket_path = socket_path();
    let app = App {
        state: Arc::new(State::new()),
        shutdown: Arc::new(Notify::new()),
        start: Instant::now(),
    };

    let router = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/interfaces", get(interfaces))
        .route("/api/v1/interfaces/{interface}/attach", post(attach))
        .route("/api/v1/interfaces/{interface}/detach", post(detach))
        .route("/api/v1/interfaces/{interface}/clean", post(clean))
        .route("/api/v1/shutdown", post(shutdown))
        .with_state(app.clone());

    // Under systemd RuntimeDirectory makes this; created here
    // too so a direct run works.
    if let Some(parent) = std::path::Path::new(&socket_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("Failed to create {}: {error}", parent.display()));
    }
    // A stale socket from a crashed daemon would block the
    // bind.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .unwrap_or_else(|error| panic!("Failed to bind {socket_path}: {error}"));
    // Root-only: filesystem permissions are the authorization.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .expect("Failed to restrict the control socket.");
    eprintln!("mangoneld: listening on {socket_path}");
    // Tell systemd (Type=notify) the socket is up; a no-op when
    // not launched under systemd.
    notify("READY=1\n");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(app.shutdown.clone()))
        .await
        .expect("The control server failed.");

    notify("STOPPING=1\n");
    eprintln!("mangoneld: detaching and exiting");
    app.state.detach_all();
    let _ = std::fs::remove_file(&socket_path);
}

/// Sends a state line to systemd's notification socket when
/// launched under `Type=notify`, else a no-op. Best effort:
/// a failed notification is not fatal.
fn notify(state: &str) {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let socket = socket.as_bytes();
    if socket.is_empty() {
        return;
    }

    // SAFETY: an all-zero sockaddr_un is a valid empty AF_UNIX
    // address; the family and path are filled in below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX)
        .expect("AF_UNIX does not fit sa_family_t. This is a bug.");

    // A leading '@' means the abstract namespace, encoded as a
    // leading NUL byte followed by the name.
    let is_abstract = socket[0] == b'@';
    let name = if is_abstract { &socket[1..] } else { socket };
    let start = usize::from(is_abstract);
    if start + name.len() > size_of_val(&address.sun_path) {
        return;
    }
    // Copy as bytes: sun_path is c_char, whose signedness is
    // platform-dependent, so a per-byte cast is not portable.
    // SAFETY: the bound above keeps the write inside sun_path.
    unsafe {
        let destination = address.sun_path.as_mut_ptr().cast::<u8>().add(start);
        std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
    }
    // Address length: everything before sun_path, plus the
    // bytes written. Filesystem paths carry a trailing NUL
    // (already zeroed); abstract names do not.
    let base = size_of::<libc::sockaddr_un>() - size_of_val(&address.sun_path);
    let used = start + name.len() + usize::from(!is_abstract);
    let Ok(address_len) = libc::socklen_t::try_from(base + used) else {
        return;
    };

    // SAFETY: an unbound datagram socket may sendto a named
    // address; the pointer and length describe a valid
    // sockaddr_un. The result is ignored — notification is best
    // effort — and the fd is always closed.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return;
        }
        libc::sendto(
            fd,
            state.as_ptr().cast(),
            state.len(),
            libc::MSG_NOSIGNAL,
            (&raw const address).cast(),
            address_len,
        );
        libc::close(fd);
    }
}

/// Reads `--socket <path>`, else the well-known default.
fn socket_path() -> String {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--socket" {
            return arguments.next().expect("--socket needs a path argument");
        }
    }

    api::DEFAULT_SOCKET_PATH.to_owned()
}

async fn status(AxumState(app): AxumState<App>) -> Json<api::StatusResponse> {
    let interfaces = app
        .state
        .status()
        .into_iter()
        .map(|interface| interface.interface)
        .collect();

    Json(api::StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_seconds: app.start.elapsed().as_secs(),
        interfaces,
    })
}

async fn stats(AxumState(app): AxumState<App>) -> Json<api::StatsResponse> {
    let interfaces = app
        .state
        .status()
        .into_iter()
        .map(|interface| api::InterfaceStats {
            interface: interface.interface,
            zero_copy: interface.zero_copy,
            queues: interface.queues,
        })
        .collect();

    Json(api::StatsResponse { interfaces })
}

async fn interfaces(
    AxumState(app): AxumState<App>,
) -> Result<Json<api::InterfacesResponse>, ApiError> {
    let state = app.state.clone();
    // Opening each interface is a handful of sysfs reads and
    // ioctls; off the reactor thread for uniformity.
    let interfaces = spawn_state(move || state.interfaces())
        .await?
        .into_iter()
        .map(|interface| api::Interface {
            mac: format_mac(interface.mac),
            name: interface.name,
            index: interface.index,
            mtu: interface.mtu,
            up: interface.up,
            running: interface.running,
            xdp_queues: interface.xdp_queues,
            numa_node: interface.numa_node,
            driver: interface.driver,
            attached: interface.attached,
        })
        .collect();

    Ok(Json(api::InterfacesResponse { interfaces }))
}

fn format_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;

    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

async fn attach(
    AxumState(app): AxumState<App>,
    Path(interface): Path<String>,
) -> Result<StatusCode, ApiError> {
    let state = app.state.clone();
    // bind() maps memory and loads an XDP program — seconds of
    // blocking work — so it runs off the reactor thread.
    spawn_state(move || state.attach(&interface)).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn detach(
    AxumState(app): AxumState<App>,
    Path(interface): Path<String>,
) -> Result<StatusCode, ApiError> {
    let state = app.state.clone();
    // Joins the interface's workers; off the reactor thread as
    // above.
    spawn_state(move || state.detach(&interface)).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn clean(
    AxumState(app): AxumState<App>,
    Path(interface): Path<String>,
) -> Result<StatusCode, ApiError> {
    let state = app.state.clone();
    // Detaches a leftover XDP program; off the reactor thread
    // as the others.
    spawn_state(move || state.clean(&interface)).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn shutdown(AxumState(app): AxumState<App>) -> StatusCode {
    // Wakes the graceful-shutdown future; teardown runs in
    // main.
    app.shutdown.notify_one();

    StatusCode::NO_CONTENT
}

/// Runs a blocking [`State`] call on the blocking pool,
/// flattening a task panic and a [`StateError`] into an
/// [`ApiError`].
async fn spawn_state<F, T>(operation: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, StateError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the operation panicked".to_owned(),
            )
        })?
        .map_err(ApiError::from)
}

/// Resolves on SIGINT, SIGTERM, or an API shutdown request,
/// whichever comes first.
async fn shutdown_signal(request: Arc<Notify>) {
    let interrupt = async {
        signal::ctrl_c().await.ok();
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install the SIGTERM handler.")
            .recv()
            .await;
    };
    let requested = async {
        request.notified().await;
    };

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
        () = requested => {},
    }
}

/// A status code and message, rendered as an
/// [`api::ErrorResponse`] body.
struct ApiError(StatusCode, String);

impl From<StateError> for ApiError {
    fn from(error: StateError) -> Self {
        let code = match &error {
            StateError::AlreadyAttached(_) | StateError::AttachedCannotClean(_) => {
                StatusCode::CONFLICT
            }
            StateError::NotAttached(_) => StatusCode::NOT_FOUND,
            StateError::NoCores | StateError::Nic(_) | StateError::Xdp(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        Self(code, error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(api::ErrorResponse { error: self.1 })).into_response()
    }
}
