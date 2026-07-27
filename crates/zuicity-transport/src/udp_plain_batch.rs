use std::{
    io,
    net::{IpAddr, SocketAddr},
};

pub(super) const CLIENT_PLAIN_BATCH_DATAGRAMS: usize = 88;
pub(super) const SERVER_PLAIN_BATCH_DATAGRAMS: usize = 96;
#[cfg(test)]
pub(super) const TEST_PLAIN_BATCH_DATAGRAMS: usize = 20;
pub(super) const MAX_PLAIN_BATCH_DATAGRAMS: usize = 128;

#[derive(Clone, Copy, Debug)]
pub(super) struct PlainTransmit<'a> {
    pub(super) destination: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) contents: &'a [u8],
    pub(super) segment_size: Option<usize>,
    pub(super) src_ip: Option<IpAddr>,
}

impl<'a> PlainTransmit<'a> {
    pub(super) fn borrow(transmit: &'a quinn::udp::Transmit<'_>) -> io::Result<Self> {
        Self::new(
            transmit.destination,
            transmit.ecn,
            transmit.contents,
            transmit.segment_size,
            transmit.src_ip,
        )
    }

    fn new(
        destination: SocketAddr,
        ecn: Option<quinn::udp::EcnCodepoint>,
        contents: &'a [u8],
        segment_size: Option<usize>,
        src_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        let transmit = Self {
            destination,
            ecn,
            contents,
            segment_size,
            src_ip,
        };
        if transmit.datagram_count() > MAX_PLAIN_BATCH_DATAGRAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary UDP batch exceeds the 128-datagram sender capacity",
            ));
        }
        Ok(transmit)
    }

    pub(super) fn datagrams(self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        self.contents.chunks(self.normalized_segment_size())
    }

    pub(super) fn datagram_lengths(self) -> impl ExactSizeIterator<Item = usize> + 'a {
        self.datagrams().map(<[u8]>::len)
    }

    pub(super) fn datagram_count(self) -> usize {
        self.datagrams().len()
    }

    pub(super) fn sent_prefix(self, sent_lengths: &[usize]) -> io::Result<(usize, bool)> {
        if sent_lengths.len() > self.datagram_count() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let full_prefix = sent_lengths
            .iter()
            .zip(self.datagram_lengths())
            .take_while(|(actual, expected)| **actual == *expected)
            .count();
        Ok((full_prefix, full_prefix == sent_lengths.len()))
    }

    fn normalized_segment_size(self) -> usize {
        self.segment_size.unwrap_or(self.contents.len()).max(1)
    }
}

#[derive(Clone, Debug)]
pub(super) struct OwnedTransmit {
    destination: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    contents: Vec<u8>,
    segment_size: Option<usize>,
    src_ip: Option<IpAddr>,
    start: usize,
}

impl OwnedTransmit {
    #[cfg(test)]
    pub(super) fn copy_from(transmit: &quinn::udp::Transmit<'_>) -> io::Result<Self> {
        Self::copy_suffix(PlainTransmit::borrow(transmit)?, 0)
    }

    pub(super) fn copy_suffix(transmit: PlainTransmit<'_>, count: usize) -> io::Result<Self> {
        if count > transmit.datagram_count() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let accepted_bytes: usize = transmit.datagram_lengths().take(count).sum();
        let suffix = transmit
            .contents
            .get(accepted_bytes..)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let mut contents = Vec::new();
        contents
            .try_reserve_exact(suffix.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        contents.extend_from_slice(suffix);
        let owned = Self {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
            start: 0,
        };
        Ok(owned)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.start == self.contents.len()
    }

    pub(super) fn transmit(&self) -> PlainTransmit<'_> {
        PlainTransmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: &self.contents[self.start..],
            segment_size: self.segment_size,
            src_ip: self.src_ip,
        }
    }

    fn advance(&mut self, bytes: usize) -> io::Result<()> {
        self.start = self
            .start
            .checked_add(bytes)
            .filter(|start| *start <= self.contents.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn storage_capacity(&self) -> usize {
        self.contents.capacity()
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
        let (full_prefix, all_full) = self.transmit().sent_prefix(sent_lengths)?;
        if !all_full {
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
        let accepted_bytes: usize = self.transmit().datagram_lengths().take(count).sum();
        self.transmit.advance(accepted_bytes)?;
        if self.transmit.is_empty() {
            Ok(ProgressDecision::Complete)
        } else {
            Ok(ProgressDecision::Pending)
        }
    }

    pub(super) fn transmit(&self) -> PlainTransmit<'_> {
        self.transmit.transmit()
    }

    pub(super) fn remaining_datagrams(&self) -> usize {
        self.transmit().datagram_count()
    }

    #[cfg(test)]
    pub(super) fn storage_capacity(&self) -> usize {
        self.transmit.storage_capacity()
    }
}

#[cfg(test)]
#[path = "udp_plain_batch_tests.rs"]
mod tests;
