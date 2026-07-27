use std::{io, sync::atomic::Ordering, time::Duration};

use crate::{
    udp_plain_batch::{BatchProgress, OwnedTransmit, PlainTransmit, ProgressDecision},
    udp_plain_syscall::PlainBatchIo,
    udp_state::PlainSendCounters,
};

const SUFFIX_COMPLETION_BUDGET: Duration = Duration::from_millis(1);

pub(super) fn send(
    io: &PlainBatchIo,
    counters: &PlainSendCounters,
    transmit: &quinn::udp::Transmit<'_>,
) -> io::Result<()> {
    let borrowed = PlainTransmit::borrow(transmit)?;
    let offered = borrowed.datagram_count();
    let sent_lengths = io.attempt(counters, borrowed)?;
    let (accepted, all_full) = borrowed.sent_prefix(&sent_lengths)?;
    record_accepted(counters, offered, accepted);
    if !all_full || accepted == 0 {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    if accepted == offered {
        return Ok(());
    }

    let mut progress = BatchProgress::new(OwnedTransmit::copy_suffix(borrowed, accepted)?);
    let deadline = std::time::Instant::now() + SUFFIX_COMPLETION_BUDGET;
    loop {
        let offered = progress.remaining_datagrams();
        let sent_lengths = match io.attempt(counters, progress.transmit()) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Err(error) = io.wait_writable(deadline) {
                    return if error.kind() == io::ErrorKind::WouldBlock {
                        Err(io::Error::from(io::ErrorKind::TimedOut))
                    } else {
                        Err(error)
                    };
                }
                continue;
            }
            Err(error) => return Err(error),
            Ok(sent_lengths) => sent_lengths,
        };
        let decision = progress.record_sent(&sent_lengths);
        let accepted = offered - progress.remaining_datagrams();
        record_accepted(counters, offered, accepted);
        match decision {
            Ok(ProgressDecision::Complete) => return Ok(()),
            Ok(ProgressDecision::Pending) => {}
            Err(error) => return Err(error),
        }
    }
}

fn record_accepted(counters: &PlainSendCounters, offered: usize, accepted: usize) {
    if accepted == 0 {
        return;
    }
    counters
        .sendmmsg_datagrams
        .fetch_add(accepted as u64, Ordering::Relaxed);
    if accepted < offered {
        counters.partial_prefixes.fetch_add(1, Ordering::Relaxed);
    }
}
