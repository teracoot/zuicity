//! Test fixtures and helpers for Juicity upstream interoperability.

use std::{
    fs::{self, OpenOptions},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Mutex, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use zuicity_protocol::AtomicCounter64;

static ARTIFACT_COUNTER: AtomicCounter64 = AtomicCounter64::new(0);

/// Default artifact directory used by parity and interop tests.
pub const DEFAULT_ARTIFACT_DIR: &str = "/tmp/zuicity-testkit";

/// Paths to upstream binaries built by the inventory/interop harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamBinaries {
    /// `juicity-client` binary path.
    pub client: PathBuf,
    /// `juicity-server` binary path.
    pub server: PathBuf,
}

impl UpstreamBinaries {
    /// Creates a binary path set from a directory.
    #[must_use]
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            client: dir.join("juicity-client"),
            server: dir.join("juicity-server"),
        }
    }
}

/// Builder for a per-test artifact directory under [`DEFAULT_ARTIFACT_DIR`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDirBuilder {
    label: String,
}

impl ArtifactDirBuilder {
    /// Creates the artifact directory and returns its path handle.
    pub fn create(&self) -> anyhow::Result<ArtifactDir> {
        let root = Path::new(DEFAULT_ARTIFACT_DIR);
        fs::create_dir_all(root)?;
        let path = root.join(unique_artifact_name(&self.label));
        fs::create_dir_all(&path)?;
        Ok(ArtifactDir { path })
    }
}

/// Created artifact directory path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDir {
    path: PathBuf,
}

impl ArtifactDir {
    /// Returns the artifact directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Builds a sanitized, unique artifact directory name from a human-readable label.
#[must_use]
pub fn artifact_dir(label: &str) -> ArtifactDirBuilder {
    ArtifactDirBuilder {
        label: sanitize_label(label),
    }
}

/// PEM certificate/key fixture written to disk for upstream and Rust server tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertFixture {
    /// Full certificate chain PEM path.
    pub cert_path: PathBuf,
    /// Private key PEM path.
    pub key_path: PathBuf,
    /// Certificate common name.
    pub common_name: String,
}

/// Writes a self-signed certificate fixture with upstream-compatible file names.
pub fn write_self_signed_cert_fixture(
    dir: &Path,
    common_name: &str,
) -> anyhow::Result<CertFixture> {
    fs::create_dir_all(dir)?;
    let cert = rcgen::generate_simple_self_signed(vec![common_name.to_owned()])?;
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("private.key");
    fs::write(&cert_path, cert.cert.pem())?;
    fs::write(&key_path, cert.key_pair.serialize_pem())?;
    Ok(CertFixture {
        cert_path,
        key_path,
        common_name: common_name.to_owned(),
    })
}

/// Reserves a loopback TCP listener on an ephemeral port.
pub fn reserve_tcp_listener() -> anyhow::Result<TcpListener> {
    Ok(TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?)
}

/// Reserves a loopback UDP socket on an ephemeral port.
pub fn reserve_udp_socket() -> anyhow::Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?)
}

/// Default attempts for [`retry_on_addr_in_use`].
pub const ADDR_IN_USE_RETRY_ATTEMPTS: usize = 6;

/// Returns true when the error chain contains an `AddrInUse` I/O error.
///
/// Tests that reserve an ephemeral loopback port, drop it, then rebind it (often
/// in a subprocess) have a TOCTOU window where another concurrently running test
/// binary can steal the port, surfacing as `AddrInUse` (errno 98). This detects
/// exactly that transient collision so it can be retried without masking real
/// failures.
pub fn is_addr_in_use_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = current {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::AddrInUse {
                return true;
            }
        }
        current = err.source();
    }
    false
}

/// Runs an async test body, retrying only on transient `AddrInUse` loopback port
/// collisions. Any other error fails immediately on the first attempt.
pub async fn retry_on_addr_in_use<F, Fut>(mut body: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let mut last: Option<Box<dyn std::error::Error>> = None;
    for attempt in 0..ADDR_IN_USE_RETRY_ATTEMPTS {
        match body().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                if is_addr_in_use_error(error.as_ref()) && attempt + 1 < ADDR_IN_USE_RETRY_ATTEMPTS
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    last = Some(error);
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| "addr-in-use retry exhausted without error".into()))
}

/// Cross-binary serialization guard for heavyweight subprocess relay tests.
///
/// Many `--all-targets` test binaries run in parallel. Tests that spawn an
/// upstream subprocess and drive a multi-hop relay starve the CPU and flake
/// (port races, slow handshakes, mid-establishment resets). This guard takes a
/// system-wide advisory lock via atomic exclusive file creation so at most one
/// such test runs at a time across every binary. The lock file is removed on
/// drop, so a panicking test still releases it.
#[derive(Debug)]
pub struct HeavySubprocessTestGuard {
    lock_path: PathBuf,
}

impl HeavySubprocessTestGuard {
    /// Acquires the global heavyweight-subprocess test lock, spinning until free.
    pub fn acquire() -> Self {
        let lock_path = std::env::temp_dir().join("zuicity-heavy-subprocess-test.lock");
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Self { lock_path },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }
}

impl Drop for HeavySubprocessTestGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Reserves the same loopback ephemeral port in both TCP and UDP protocol spaces.
pub fn reserve_tcp_udp_pair() -> anyhow::Result<(TcpListener, UdpSocket)> {
    for _ in 0..128 {
        let tcp = reserve_tcp_listener()?;
        let addr = tcp.local_addr()?;
        match UdpSocket::bind(addr) {
            Ok(udp) => return Ok((tcp, udp)),
            Err(_) => continue,
        }
    }
    Err(anyhow::anyhow!(
        "failed to reserve a loopback port free for both TCP and UDP"
    ))
}

/// Bounded TCP echo server used by interop tests.
#[derive(Debug)]
pub struct TcpEchoServer {
    local_addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl TcpEchoServer {
    /// Starts a TCP echo server bound to `127.0.0.1:0`.
    pub async fn start() -> anyhow::Result<Self> {
        let std_listener = reserve_tcp_listener()?;
        std_listener.set_nonblocking(true)?;
        let local_addr = std_listener.local_addr()?;
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return Ok(()),
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted?;
                        tokio::spawn(async move {
                            let mut buf = [0_u8; 8192];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                }
            }
        });
        Ok(Self {
            local_addr,
            shutdown,
            task,
        })
    }

    /// Returns the bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops the server and waits for its task to exit.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        self.task.await??;
        Ok(())
    }
}

/// Bounded UDP echo server used by interop tests.
#[derive(Debug)]
pub struct UdpEchoServer {
    local_addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl UdpEchoServer {
    /// Starts a UDP echo server bound to `127.0.0.1:0`.
    pub async fn start() -> anyhow::Result<Self> {
        let std_socket = reserve_udp_socket()?;
        std_socket.set_nonblocking(true)?;
        let local_addr = std_socket.local_addr()?;
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut buf = vec![0_u8; 65_535];
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return Ok(()),
                    received = socket.recv_from(&mut buf) => {
                        let (n, peer) = received?;
                        socket.send_to(&buf[..n], peer).await?;
                    }
                }
            }
        });
        Ok(Self {
            local_addr,
            shutdown,
            task,
        })
    }

    /// Returns the bound local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops the server and waits for its task to exit.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        self.task.await??;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5ConnectRequest {
    pub target: SocketAddr,
}

pub async fn start_socks5_tcp_connect_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<Socks5ConnectRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        inbound.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS version",
            ));
        }
        let mut methods = vec![0_u8; greeting[1] as usize];
        inbound.read_exact(&mut methods).await?;
        if !methods.contains(&0x00) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 client did not offer no-auth",
            ));
        }
        inbound.write_all(&[0x05, 0x00]).await?;

        let mut request = [0_u8; 4];
        inbound.read_exact(&mut request).await?;
        if request[..3] != [0x05, 0x01, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 CONNECT request",
            ));
        }
        let target = match request[3] {
            0x01 => {
                let mut raw = [0_u8; 6];
                inbound.read_exact(&mut raw).await?;
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                    u16::from_be_bytes([raw[4], raw[5]]),
                )
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test proxy only supports IPv4 CONNECT targets",
                ));
            }
        };
        request_tx
            .send(Socks5ConnectRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;
        let mut outbound = tokio::net::TcpStream::connect(target).await?;
        inbound
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5UdpAssociateRequest {
    pub target: SocketAddr,
}

pub async fn start_socks5_udp_associate_proxy() -> std::io::Result<(
    SocketAddr,
    tokio::sync::mpsc::Receiver<Socks5UdpAssociateRequest>,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (request_tx, request_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        control.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS version",
            ));
        }
        let mut methods = vec![0_u8; greeting[1] as usize];
        control.read_exact(&mut methods).await?;
        if !methods.contains(&0x00) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 client did not offer no-auth",
            ));
        }
        control.write_all(&[0x05, 0x00]).await?;

        let mut request = [0_u8; 4];
        control.read_exact(&mut request).await?;
        if request[..3] != [0x05, 0x03, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP ASSOCIATE request",
            ));
        }
        match request[3] {
            0x01 => {
                let mut raw = [0_u8; 6];
                control.read_exact(&mut raw).await?;
            }
            0x03 => {
                let mut len = [0_u8; 1];
                control.read_exact(&mut len).await?;
                let mut raw = vec![0_u8; len[0] as usize + 2];
                control.read_exact(&mut raw).await?;
            }
            0x04 => {
                let mut raw = [0_u8; 18];
                control.read_exact(&mut raw).await?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported UDP ASSOCIATE address type",
                ));
            }
        }

        let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let relay_addr = udp.local_addr()?;
        let relay_port = relay_addr.port().to_be_bytes();
        control
            .write_all(&[
                0x05,
                0x00,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                relay_port[0],
                relay_port[1],
            ])
            .await?;

        let mut datagram = vec![0_u8; 65_535];
        let (received, client_udp_addr) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            udp.recv_from(&mut datagram),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP packet"))??;
        if received < 10 || datagram[..4] != [0x00, 0x00, 0x00, 0x01] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP datagram header",
            ));
        }
        let target = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                datagram[4],
                datagram[5],
                datagram[6],
                datagram[7],
            )),
            u16::from_be_bytes([datagram[8], datagram[9]]),
        );
        let payload = datagram[10..received].to_vec();
        request_tx
            .send(Socks5UdpAssociateRequest { target })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request channel closed")
            })?;

        udp.send_to(&payload, target).await?;
        let (response_len, response_peer) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            udp.recv_from(&mut datagram),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no UDP response"))??;
        let IpAddr::V4(peer_ip) = response_peer.ip() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test proxy only supports IPv4 UDP responses",
            ));
        };
        let peer_port = response_peer.port().to_be_bytes();
        let mut encoded = Vec::with_capacity(10 + response_len);
        encoded.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        encoded.extend_from_slice(&peer_ip.octets());
        encoded.extend_from_slice(&peer_port);
        encoded.extend_from_slice(&datagram[..response_len]);
        udp.send_to(&encoded, client_udp_addr).await?;
        let mut drain = [0_u8; 1];
        let _ = control.read(&mut drain).await;
        Ok(())
    });
    Ok((local_addr, request_rx, task))
}

/// Builder for a managed child process with stdout/stderr redirected to one log file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProcessBuilder {
    program: String,
    args: Vec<String>,
    log_path: Option<PathBuf>,
}

impl ManagedProcessBuilder {
    /// Creates a process builder for `program`.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            log_path: None,
        }
    }

    /// Adds one command-line argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Sets the combined stdout/stderr log path.
    #[must_use]
    pub fn log_path(mut self, log_path: impl AsRef<Path>) -> Self {
        self.log_path = Some(log_path.as_ref().to_path_buf());
        self
    }

    /// Starts the process and returns a managed handle.
    pub fn start(self) -> anyhow::Result<ManagedProcess> {
        let log_path = self.log_path.unwrap_or_else(default_process_log_path);
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let stderr = log.try_clone()?;
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        let child = command
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let pid = child.id();
        Ok(ManagedProcess {
            pid,
            log_path,
            child: Mutex::new(Some(child)),
        })
    }
}

/// Managed child process used by upstream interop harnesses.
#[derive(Debug)]
pub struct ManagedProcess {
    pid: u32,
    log_path: PathBuf,
    child: Mutex<Option<Child>>,
}

impl ManagedProcess {
    /// Returns the operating-system process id.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the combined stdout/stderr log path.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Returns whether the process is still running.
    pub fn is_running(&self) -> anyhow::Result<bool> {
        let mut guard = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("managed process mutex poisoned"))?;
        let Some(child) = guard.as_mut() else {
            return Ok(false);
        };
        if child.try_wait()?.is_some() {
            *guard = None;
            return Ok(false);
        }
        Ok(true)
    }

    /// Waits until the process log contains `needle`.
    pub fn wait_for_log_contains(&self, needle: &str, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if fs::read_to_string(&self.log_path)
                .map(|log| log.contains(needle))
                .unwrap_or(false)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for {:?} in {}",
                    needle,
                    self.log_path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Sends SIGTERM, waits up to `timeout`, then sends SIGKILL if needed.
    pub fn terminate(&mut self, timeout: Duration) -> anyhow::Result<ManagedProcessExit> {
        self.terminate_inner(timeout)
    }

    fn terminate_inner(&self, timeout: Duration) -> anyhow::Result<ManagedProcessExit> {
        let mut guard = self
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("managed process mutex poisoned"))?;
        let Some(child) = guard.as_mut() else {
            anyhow::bail!("managed process {} already exited", self.pid);
        };

        send_signal(self.pid, "TERM")?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                *guard = None;
                return Ok(ManagedProcessExit {
                    pid: self.pid,
                    status,
                    forced: false,
                });
            }
            if Instant::now() >= deadline {
                child.kill()?;
                let status = child.wait()?;
                *guard = None;
                return Ok(ManagedProcessExit {
                    pid: self.pid,
                    status,
                    forced: true,
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = send_signal(self.pid, "TERM");
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Ok(None) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}

/// Exit report returned by [`ManagedProcess::terminate`].
#[derive(Debug)]
pub struct ManagedProcessExit {
    /// Process id.
    pub pid: u32,
    /// Exit status.
    pub status: ExitStatus,
    /// Whether SIGKILL was needed after graceful termination timed out.
    pub forced: bool,
}

/// Waits for an arbitrary process id to exit.
pub fn wait_for_process_exit(pid: u32, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_exists(pid)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for process {pid} to exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn default_process_log_path() -> PathBuf {
    Path::new(DEFAULT_ARTIFACT_DIR).join("managed-process.log")
}

fn send_signal(pid: u32, signal: &str) -> anyhow::Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("kill -{signal} {pid} exited with {status}");
    }
}

fn process_exists(pid: u32) -> anyhow::Result<bool> {
    let status = Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

fn unique_artifact_name(label: &str) -> String {
    let pid = std::process::id();
    let seq = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{label}-{pid}-{nanos}-{seq}")
}

fn sanitize_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len().max(1));
    let mut last_was_dash = false;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "artifact".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, net::SocketAddr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };

    #[test]
    fn artifact_dir_creates_sanitized_unique_directory() -> anyhow::Result<()> {
        let dir = artifact_dir("server lifecycle/auth").create()?;
        assert!(dir.path().starts_with(DEFAULT_ARTIFACT_DIR));
        assert!(dir.path().is_dir());
        assert!(
            dir.path()
                .to_string_lossy()
                .contains("server-lifecycle-auth")
        );
        fs::write(dir.path().join("probe.txt"), b"ok")?;
        Ok(())
    }

    #[test]
    fn self_signed_cert_fixture_writes_cert_and_key_files() -> anyhow::Result<()> {
        let dir = artifact_dir("cert fixture").create()?;
        let cert = write_self_signed_cert_fixture(dir.path(), "example.com")?;
        assert_eq!(cert.common_name, "example.com");
        assert_eq!(cert.cert_path, dir.path().join("fullchain.pem"));
        assert_eq!(cert.key_path, dir.path().join("private.key"));
        let cert_pem = fs::read_to_string(&cert.cert_path)?;
        let key_pem = fs::read_to_string(&cert.key_path)?;
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        Ok(())
    }

    #[test]
    fn reserved_local_addresses_use_loopback_ephemeral_ports() -> anyhow::Result<()> {
        let tcp = reserve_tcp_listener()?;
        let udp = reserve_udp_socket()?;
        let (paired_tcp, paired_udp) = reserve_tcp_udp_pair()?;
        assert_eq!(
            tcp.local_addr()?.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            udp.local_addr()?.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(paired_tcp.local_addr()?.ip(), paired_udp.local_addr()?.ip());
        assert_eq!(
            paired_tcp.local_addr()?.port(),
            paired_udp.local_addr()?.port()
        );
        assert_ne!(tcp.local_addr()?.port(), 0);
        assert_ne!(udp.local_addr()?.port(), 0);
        assert_ne!(paired_tcp.local_addr()?.port(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn tcp_echo_server_round_trips_bytes_and_shuts_down() -> anyhow::Result<()> {
        let server = TcpEchoServer::start().await?;
        let mut stream = timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(server.local_addr()),
        )
        .await??;
        stream.write_all(b"juicity-tcp").await?;
        let mut buf = [0_u8; 11];
        timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await??;
        assert_eq!(&buf, b"juicity-tcp");
        drop(stream);
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn udp_echo_server_round_trips_datagrams_and_shuts_down() -> anyhow::Result<()> {
        let server = UdpEchoServer::start().await?;
        let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        socket.send_to(b"juicity-udp", server.local_addr()).await?;
        let mut buf = [0_u8; 64];
        let (n, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await??;
        assert_eq!(from, server.local_addr());
        assert_eq!(&buf[..n], b"juicity-udp");
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn async_tcp_echo_server_works_with_tokio_clients() -> anyhow::Result<()> {
        let server = TcpEchoServer::start().await?;
        let mut stream = tokio::net::TcpStream::connect(server.local_addr()).await?;
        stream.write_all(b"async").await?;
        let mut buf = [0_u8; 5];
        timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await??;
        assert_eq!(&buf, b"async");
        server.shutdown().await?;
        Ok(())
    }

    #[test]
    fn managed_process_records_pid_log_readiness_and_teardown() -> anyhow::Result<()> {
        let dir = artifact_dir("managed process").create()?;
        let log_path = dir.path().join("process.log");
        let mut process = ManagedProcessBuilder::new("sh")
            .arg("-c")
            .arg("echo process-ready; trap 'echo process-teardown; exit 0' TERM; while true; do sleep 1; done")
            .log_path(&log_path)
            .start()?;

        assert_ne!(process.pid(), 0);
        assert_eq!(process.log_path(), log_path.as_path());
        process.wait_for_log_contains("process-ready", Duration::from_secs(2))?;
        assert!(process.is_running()?);

        let exit = process.terminate(Duration::from_secs(2))?;
        assert_eq!(exit.pid, process.pid());
        assert!(exit.status.success(), "exit={exit:?}");
        assert!(!exit.forced, "process should handle SIGTERM gracefully");
        assert!(!process.is_running()?);
        process.wait_for_log_contains("process-teardown", Duration::from_secs(2))?;
        let log = fs::read_to_string(&log_path)?;
        assert!(log.contains("process-ready"));
        assert!(log.contains("process-teardown"));
        Ok(())
    }

    #[test]
    fn managed_process_drop_reaps_child_and_preserves_log() -> anyhow::Result<()> {
        let dir = artifact_dir("managed drop").create()?;
        let log_path = dir.path().join("drop.log");
        let pid = {
            let process = ManagedProcessBuilder::new("sh")
                .arg("-c")
                .arg("echo drop-ready; while true; do sleep 1; done")
                .log_path(&log_path)
                .start()?;
            process.wait_for_log_contains("drop-ready", Duration::from_secs(2))?;
            assert!(process.is_running()?);
            process.pid()
        };

        wait_for_process_exit(pid, Duration::from_secs(2))?;
        let log = fs::read_to_string(&log_path)?;
        assert!(log.contains("drop-ready"));
        Ok(())
    }
}
