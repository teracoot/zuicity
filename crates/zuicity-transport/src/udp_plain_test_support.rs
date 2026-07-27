use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};

use arrayvec::ArrayVec;

use crate::udp_plain_batch::{MAX_PLAIN_BATCH_DATAGRAMS, PlainTransmit};

#[derive(Clone, Debug)]
pub(crate) enum ScriptedAttempt {
    Accepted(usize),
    AcceptedLengths(Vec<usize>),
    WouldBlock,
    Error(io::ErrorKind),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ScriptedPoll {
    Writable,
    TimedOut,
}

#[derive(Clone, Debug)]
pub(crate) struct PlainSendTestHook {
    state: Arc<HookState>,
}

#[derive(Debug)]
struct HookState {
    attempts: Mutex<VecDeque<ScriptedAttempt>>,
    offered: Mutex<Vec<Vec<Vec<u8>>>>,
    polls: Mutex<VecDeque<ScriptedPoll>>,
}

impl PlainSendTestHook {
    pub(crate) fn scripted(attempts: impl IntoIterator<Item = ScriptedAttempt>) -> Self {
        Self {
            state: Arc::new(HookState {
                attempts: Mutex::new(attempts.into_iter().collect()),
                offered: Mutex::new(Vec::new()),
                polls: Mutex::new(VecDeque::new()),
            }),
        }
    }

    pub(crate) fn with_polls(self, polls: impl IntoIterator<Item = ScriptedPoll>) -> Self {
        if let Ok(mut scripted) = self.state.polls.lock() {
            scripted.extend(polls);
        }
        self
    }

    pub(crate) fn attempt(
        &self,
        transmit: PlainTransmit<'_>,
    ) -> io::Result<ArrayVec<usize, MAX_PLAIN_BATCH_DATAGRAMS>> {
        self.state
            .offered
            .lock()
            .map_err(|_| io::Error::other("plain send test offers lock poisoned"))?
            .push(transmit.datagrams().map(<[u8]>::to_vec).collect());
        let scripted = self
            .state
            .attempts
            .lock()
            .map_err(|_| io::Error::other("plain send test attempts lock poisoned"))?
            .pop_front()
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        match scripted {
            ScriptedAttempt::Accepted(count) => Ok(transmit
                .datagram_lengths()
                .take(count)
                .collect::<ArrayVec<_, MAX_PLAIN_BATCH_DATAGRAMS>>()),
            ScriptedAttempt::AcceptedLengths(lengths) => Ok(lengths
                .into_iter()
                .collect::<ArrayVec<_, MAX_PLAIN_BATCH_DATAGRAMS>>()),
            ScriptedAttempt::WouldBlock => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            ScriptedAttempt::Error(kind) => Err(io::Error::from(kind)),
        }
    }

    pub(crate) fn poll_writable(&self) -> io::Result<()> {
        let scripted = self
            .state
            .polls
            .lock()
            .map_err(|_| io::Error::other("plain send test polls lock poisoned"))?
            .pop_front()
            .unwrap_or(ScriptedPoll::TimedOut);
        match scripted {
            ScriptedPoll::Writable => Ok(()),
            ScriptedPoll::TimedOut => Err(io::Error::from(io::ErrorKind::TimedOut)),
        }
    }

    pub(crate) fn offered(&self) -> Vec<Vec<Vec<u8>>> {
        self.state
            .offered
            .lock()
            .map(|offered| offered.clone())
            .unwrap_or_default()
    }
}
