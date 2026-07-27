use std::{io, sync::atomic::Ordering, time::Duration};

use crate::{
    udp_plain_batch::{BatchProgress, OwnedTransmit, ProgressDecision},
    udp_plain_syscall::PlainBatchIo,
    udp_state::PlainSendCounters,
};

const SUFFIX_COMPLETION_BUDGET: Duration = Duration::from_millis(1);

pub(super) fn send(
    io: &PlainBatchIo,
    counters: &PlainSendCounters,
    transmit: &quinn::udp::Transmit<'_>,
) -> io::Result<()> {
    let mut progress = BatchProgress::new(OwnedTransmit::copy_from(transmit)?);
    let mut accepted_prefix = false;
    let mut deadline = None;
    loop {
        let offered = progress.remaining_datagrams();
        let sent_lengths = match io.attempt(counters, &progress) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && !accepted_prefix => {
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let completion_deadline =
                    deadline.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                if let Err(error) = io.wait_writable(completion_deadline) {
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
        if accepted > 0 {
            accepted_prefix = true;
            counters
                .sendmmsg_datagrams
                .fetch_add(accepted as u64, Ordering::Relaxed);
            if accepted < offered {
                counters.partial_prefixes.fetch_add(1, Ordering::Relaxed);
            }
        }
        match decision {
            Ok(ProgressDecision::Complete) => return Ok(()),
            Ok(ProgressDecision::Pending) => {
                if accepted > 0 && deadline.is_none() {
                    deadline = Some(std::time::Instant::now() + SUFFIX_COMPLETION_BUDGET);
                }
            }
            Err(error) => return Err(error),
        }
    }
}
