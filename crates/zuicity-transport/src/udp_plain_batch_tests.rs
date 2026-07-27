use std::{io, net::SocketAddr};

use super::*;

#[test]
fn fixed_capacity_covers_role_specific_production_batches() {
    assert_eq!(CLIENT_PLAIN_BATCH_DATAGRAMS, 88);
    assert_eq!(SERVER_PLAIN_BATCH_DATAGRAMS, 96);
    assert_eq!(MAX_PLAIN_BATCH_DATAGRAMS, 128);
}

fn owned_transmit(
    destination: SocketAddr,
    contents: &[u8],
    segment: usize,
) -> io::Result<OwnedTransmit> {
    let borrowed = quinn::udp::Transmit {
        destination,
        ecn: Some(quinn::udp::EcnCodepoint::Ect0),
        contents,
        segment_size: Some(segment),
        src_ip: Some(std::net::Ipv4Addr::LOCALHOST.into()),
    };
    OwnedTransmit::copy_from(&borrowed)
}

#[test]
fn given_three_datagrams_when_positive_prefix_commits_then_only_suffix_remains() -> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9000));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbbcccc", 4)?);

    let decision = progress.record(AttemptOutcome::Accepted(2))?;

    assert_eq!(
        decision,
        TestProgressDecision::Progress(ProgressDecision::Pending)
    );
    assert_eq!(progress.transmit().contents, b"cccc");
    assert_eq!(
        progress.transmit().datagram_lengths().collect::<Vec<_>>(),
        [4]
    );
    Ok(())
}

#[test]
fn given_reserved_owned_batch_when_prefix_commits_then_suffix_reuses_reserved_storage()
-> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9008));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbbcccc", 4)?);
    let capacity = progress.storage_capacity();

    progress.commit_prefix(2)?;

    assert_eq!(progress.transmit().contents, b"cccc");
    assert_eq!(progress.storage_capacity(), capacity);
    Ok(())
}

#[test]
fn given_fresh_batch_when_would_block_then_nothing_is_committed() -> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9001));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbb", 4)?);

    let decision = progress.record(AttemptOutcome::WouldBlock)?;

    assert_eq!(decision, TestProgressDecision::WouldBlock);
    assert_eq!(progress.transmit().contents, b"aaaabbbb");
    Ok(())
}

#[test]
fn given_committed_prefix_when_later_error_then_prefix_is_not_restored() -> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9002));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbbcccc", 4)?);
    progress.record(AttemptOutcome::Accepted(1))?;

    let decision = progress.record(AttemptOutcome::Error(io::ErrorKind::PermissionDenied))?;

    assert_eq!(
        decision,
        TestProgressDecision::Terminal(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(progress.transmit().contents, b"bbbbcccc");
    Ok(())
}

#[test]
fn given_non_multiple_payload_when_lengths_read_then_final_datagram_is_short() -> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9003));
    let transmit = owned_transmit(destination, b"aaaabbbbcc", 4)?;

    let lengths = transmit.transmit().datagram_lengths().collect::<Vec<_>>();

    assert_eq!(lengths, [4, 4, 2]);
    Ok(())
}

#[test]
fn given_distinct_metadata_when_one_batch_advances_then_other_batch_is_isolated() -> io::Result<()>
{
    let first_destination = SocketAddr::from(([127, 0, 0, 1], 9004));
    let second_destination = SocketAddr::from(([127, 0, 0, 1], 9005));
    let mut first = BatchProgress::new(owned_transmit(first_destination, b"11112222", 4)?);
    let second = BatchProgress::new(owned_transmit(second_destination, b"aaaabbbb", 4)?);

    first.record(AttemptOutcome::Accepted(1))?;

    assert_eq!(first.transmit().destination, first_destination);
    assert_eq!(first.transmit().contents, b"2222");
    assert_eq!(second.transmit().destination, second_destination);
    assert_eq!(second.transmit().contents, b"aaaabbbb");
    assert_eq!(second.transmit().ecn, Some(quinn::udp::EcnCodepoint::Ect0));
    assert_eq!(
        second.transmit().src_ip,
        Some(std::net::Ipv4Addr::LOCALHOST.into())
    );
    Ok(())
}

#[test]
fn given_nonempty_batch_when_zero_is_reported_then_write_zero_is_returned() -> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9006));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbb", 4)?);

    let error = progress
        .record(AttemptOutcome::Accepted(0))
        .expect_err("zero progress must not be accepted");

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(progress.transmit().contents, b"aaaabbbb");
    Ok(())
}

#[test]
fn given_first_datagram_with_short_byte_count_when_validated_then_whole_batch_remains()
-> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9007));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbb", 4)?);

    let error = progress
        .record_sent(&[3])
        .expect_err("an accepted UDP datagram must report its full length");

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(progress.transmit().contents, b"aaaabbbb");
    assert_eq!(progress.remaining_datagrams(), 2);
    Ok(())
}

#[test]
fn given_plain_send_red_full_first_and_short_second_when_recorded_then_short_count_keeps_incomplete_datagram()
-> io::Result<()> {
    let destination = SocketAddr::from(([127, 0, 0, 1], 9009));
    let mut progress = BatchProgress::new(owned_transmit(destination, b"aaaabbbbcccc", 4)?);

    let error = progress
        .record_sent(&[4, 3])
        .expect_err("a short UDP datagram must remain owned by the sender");

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(
        progress.transmit().contents,
        b"bbbbcccc",
        "the remaining suffix must begin at the incomplete second datagram"
    );
    Ok(())
}
