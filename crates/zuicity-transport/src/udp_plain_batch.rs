use std::{
    io,
    net::{IpAddr, SocketAddr},
};

pub(super) const MAX_PLAIN_BATCH_DATAGRAMS: usize = 10;

#[derive(Clone, Debug)]
pub(super) struct OwnedTransmit {
    pub(super) destination: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) contents: Vec<u8>,
    pub(super) segment_size: Option<usize>,
    pub(super) src_ip: Option<IpAddr>,
}

impl OwnedTransmit {
    pub(super) fn copy_from(transmit: &quinn::udp::Transmit<'_>) -> io::Result<Self> {
        let segment_size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        if transmit.contents.chunks(segment_size).len() > MAX_PLAIN_BATCH_DATAGRAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary UDP batch exceeds Quinn's 10-datagram cap",
            ));
        }
        let mut contents = Vec::new();
        contents
            .try_reserve_exact(transmit.contents.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        contents.extend_from_slice(transmit.contents);
        let owned = Self {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        Ok(owned)
    }

    pub(super) fn datagrams(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.contents.chunks(self.normalized_segment_size())
    }

    pub(super) fn datagram_lengths(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.datagrams().map(<[u8]>::len)
    }

    pub(super) fn datagram_count(&self) -> usize {
        self.datagrams().len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    #[cfg(test)]
    pub(super) fn storage_capacity(&self) -> usize {
        self.contents.capacity()
    }

    fn normalized_segment_size(&self) -> usize {
        self.segment_size.unwrap_or(self.contents.len()).max(1)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttemptOutcome {
    Accepted(usize),
    WouldBlock,
    Error(io::ErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProgressDecision {
    Complete,
    Pending,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestProgressDecision {
    Progress(ProgressDecision),
    WouldBlock,
    Terminal(io::ErrorKind),
}

#[derive(Debug)]
pub(super) struct BatchProgress {
    transmit: OwnedTransmit,
}

impl BatchProgress {
    pub(super) fn new(transmit: OwnedTransmit) -> Self {
        Self { transmit }
    }

    #[cfg(test)]
    pub(super) fn record(&mut self, outcome: AttemptOutcome) -> io::Result<TestProgressDecision> {
        match outcome {
            AttemptOutcome::Accepted(count) => self
                .commit_prefix(count)
                .map(TestProgressDecision::Progress),
            AttemptOutcome::WouldBlock => Ok(TestProgressDecision::WouldBlock),
            AttemptOutcome::Error(kind) => Ok(TestProgressDecision::Terminal(kind)),
        }
    }

    pub(super) fn record_sent(&mut self, sent_lengths: &[usize]) -> io::Result<ProgressDecision> {
        if sent_lengths.len() > self.remaining_datagrams() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let full_prefix = sent_lengths
            .iter()
            .zip(self.transmit.datagram_lengths())
            .take_while(|(actual, expected)| **actual == *expected)
            .count();
        if full_prefix != sent_lengths.len() {
            if full_prefix > 0 {
                self.commit_prefix(full_prefix)?;
            }
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.commit_prefix(full_prefix)
    }

    pub(super) fn commit_prefix(&mut self, count: usize) -> io::Result<ProgressDecision> {
        let offered = self.remaining_datagrams();
        if count > offered {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if count == 0 {
            return if offered == 0 {
                Ok(ProgressDecision::Complete)
            } else {
                Err(io::Error::from(io::ErrorKind::WriteZero))
            };
        }
        let accepted_bytes: usize = self.transmit.datagram_lengths().take(count).sum();
        self.transmit.contents.copy_within(accepted_bytes.., 0);
        self.transmit
            .contents
            .truncate(self.transmit.contents.len() - accepted_bytes);
        if self.transmit.is_empty() {
            Ok(ProgressDecision::Complete)
        } else {
            Ok(ProgressDecision::Pending)
        }
    }

    pub(super) fn transmit(&self) -> &OwnedTransmit {
        &self.transmit
    }

    pub(super) fn remaining_datagrams(&self) -> usize {
        self.transmit.datagram_count()
    }
}

#[cfg(test)]
#[path = "udp_plain_batch_tests.rs"]
mod tests;
