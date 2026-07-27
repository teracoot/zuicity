use std::{
    io, iter,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    udp_plain_direct,
    udp_plain_syscall::PlainBatchIo,
    udp_plain_test_support::{PlainSendTestHook, ScriptedAttempt, ScriptedPoll},
    udp_state::PlainSendCounters,
};

const RETRY_ATTEMPT_LIMIT: usize = 8;

fn transmit(destination: std::net::SocketAddr, contents: &[u8]) -> quinn::udp::Transmit<'_> {
    quinn::udp::Transmit {
        destination,
        ecn: None,
        contents,
        segment_size: Some(4),
        src_ip: None,
    }
}

fn io_with_hook(
    hook: PlainSendTestHook,
) -> io::Result<(PlainBatchIo, Arc<PlainSendCounters>, std::net::SocketAddr)> {
    let receiver = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let destination = receiver.local_addr()?;
    let sender = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    sender.set_nonblocking(true)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(sender)?);
    let counters = Arc::new(PlainSendCounters::default());
    let io = PlainBatchIo::with_hook(socket, hook);
    Ok((io, counters, destination))
}

#[tokio::test]
async fn given_plain_send_red_positive_prefix_and_terminal_error_when_send_plain_returns_then_terminal_is_returned_same_call()
-> io::Result<()> {
    let hook = PlainSendTestHook::scripted([ScriptedAttempt::AcceptedLengths(vec![4, 3])]);
    let (io, counters, destination) = io_with_hook(hook.clone())?;

    let error = udp_plain_direct::send(
        &io,
        counters.as_ref(),
        &transmit(destination, b"aaaabbbbcccc"),
    )
    .expect_err("terminal after accepted prefix must be returned by the same send call");

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(
        hook.offered(),
        [vec![b"aaaa".to_vec(), b"bbbb".to_vec(), b"cccc".to_vec()]]
    );
    assert_eq!(counters.sendmmsg_datagrams.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn given_plain_send_red_repeated_eintr_when_retrying_then_interrupted_attempts_are_bounded()
-> io::Result<()> {
    let attempts = iter::repeat_n(
        ScriptedAttempt::Error(io::ErrorKind::Interrupted),
        RETRY_ATTEMPT_LIMIT,
    )
    .chain([ScriptedAttempt::Error(io::ErrorKind::PermissionDenied)]);
    let hook = PlainSendTestHook::scripted(attempts);
    let (io, counters, destination) = io_with_hook(hook.clone())?;

    let error = udp_plain_direct::send(&io, counters.as_ref(), &transmit(destination, b"aaaabbbb"))
        .expect_err("the interrupted-attempt budget must end with a visible error");

    let attempt_count = hook.offered().len();
    assert!(
        attempt_count <= RETRY_ATTEMPT_LIMIT,
        "repeated EINTR used {attempt_count} attempts; maximum is {RETRY_ATTEMPT_LIMIT}"
    );
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    Ok(())
}

#[tokio::test]
async fn given_plain_send_red_positive_prefix_and_persistent_would_block_when_recovering_then_post_prefix_would_block_times_out()
-> io::Result<()> {
    let hook =
        PlainSendTestHook::scripted([ScriptedAttempt::Accepted(1), ScriptedAttempt::WouldBlock])
            .with_polls([ScriptedPoll::TimedOut]);
    let (io, counters, destination) = io_with_hook(hook)?;

    let error = udp_plain_direct::send(&io, counters.as_ref(), &transmit(destination, b"aaaabbbb"))
        .expect_err("persistent post-prefix WouldBlock must be visible in the same send call");

    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "persistent post-prefix WouldBlock must end as a visible timeout"
    );
    Ok(())
}

#[tokio::test]
async fn given_zero_progress_would_block_when_direct_send_returns_then_quinn_retains_whole_batch()
-> io::Result<()> {
    let hook = PlainSendTestHook::scripted([ScriptedAttempt::WouldBlock]);
    let (io, counters, destination) = io_with_hook(hook.clone())?;

    let error = udp_plain_direct::send(&io, counters.as_ref(), &transmit(destination, b"aaaabbbb"))
        .expect_err("zero-progress WouldBlock must return ownership to Quinn");

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(hook.offered(), [vec![b"aaaa".to_vec(), b"bbbb".to_vec()]]);
    assert_eq!(counters.sendmmsg_datagrams.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn given_cached_writable_when_initial_batch_would_block_then_tokio_readiness_is_cleared()
-> io::Result<()> {
    let hook =
        PlainSendTestHook::scripted([ScriptedAttempt::WouldBlock, ScriptedAttempt::WouldBlock]);
    let (io, counters, destination) = io_with_hook(hook)?;
    io.socket().writable().await?;

    let error = udp_plain_direct::send(&io, counters.as_ref(), &transmit(destination, b"aaaabbbb"))
        .expect_err("zero-progress WouldBlock must return ownership to Quinn");
    let readiness_probe_ran = AtomicBool::new(false);
    let probe = io.socket().try_io(tokio::io::Interest::WRITABLE, || {
        readiness_probe_ran.store(true, Ordering::Relaxed);
        Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock))
    });

    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        probe
            .expect_err("cleared readiness must remain pending")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(
        !readiness_probe_ran.load(Ordering::Relaxed),
        "the initial EAGAIN must clear Tokio writable readiness before Quinn retries"
    );
    Ok(())
}

#[tokio::test]
async fn given_recovery_eagain_when_socket_is_writable_then_only_suffix_is_retried()
-> io::Result<()> {
    let hook = PlainSendTestHook::scripted([
        ScriptedAttempt::Accepted(1),
        ScriptedAttempt::WouldBlock,
        ScriptedAttempt::Accepted(1),
    ])
    .with_polls([ScriptedPoll::Writable]);
    let (io, counters, destination) = io_with_hook(hook.clone())?;

    udp_plain_direct::send(&io, counters.as_ref(), &transmit(destination, b"aaaabbbb"))?;

    assert_eq!(
        hook.offered(),
        [
            vec![b"aaaa".to_vec(), b"bbbb".to_vec()],
            vec![b"bbbb".to_vec()],
            vec![b"bbbb".to_vec()],
        ]
    );
    assert_eq!(counters.sendmmsg_datagrams.load(Ordering::Relaxed), 2);
    Ok(())
}
