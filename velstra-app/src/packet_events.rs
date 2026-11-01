//! The agent's own window over the packet-event ring.
//!
//! The kernel ring is consume-once: whoever reads an event takes it from every
//! other reader. With the console's collector and `show firewall events` both
//! draining it, each silently stole the other's events, and nothing told either
//! of them. So the agent alone drains the ring, into this bounded log, and gives
//! every event a monotonically increasing id. A reader keeps its own cursor and
//! asks for what came after it; reading never removes anything, and a reader
//! that fell behind the window is told how many events it missed instead of
//! seeing a seamless-looking stream with a hole in it.

use std::collections::VecDeque;

use serde_json::{Value, json};

/// How many events the agent keeps. A few seconds of a busy drop storm; enough
/// for a reader polling every second to never miss one at ordinary rates.
pub const CAPACITY: usize = 4096;

pub struct PacketEventLog {
    events: VecDeque<Value>,
    /// The id the next event receives. Ids start at 1 so a cursor of 0 means
    /// "from the beginning".
    next_id: u64,
    /// Identifies this agent run. Ids restart at 1 with every run, so a reader
    /// whose cursor came from a previous one must start over, and it can tell
    /// only by the epoch changing.
    epoch: u64,
    /// The cursor of the old, cursor-less `packet-events` request, kept here so
    /// a client that predates cursors still sees each event once.
    legacy_cursor: u64,
    capacity: usize,
}

impl PacketEventLog {
    pub fn new(epoch: u64) -> Self {
        Self::with_capacity(epoch, CAPACITY)
    }

    fn with_capacity(epoch: u64, capacity: usize) -> Self {
        Self {
            events: VecDeque::new(),
            next_id: 1,
            epoch,
            legacy_cursor: 0,
            capacity,
        }
    }

    /// Record one event drained from the kernel ring, giving it the next id.
    pub fn push(&mut self, mut event: Value) {
        event["id"] = json!(self.next_id);
        self.next_id += 1;
        self.events.push_back(event);
        while self.events.len() > self.capacity {
            self.events.pop_front();
        }
    }

    fn oldest_id(&self) -> u64 {
        self.next_id - self.events.len() as u64
    }

    /// The first `limit` events after `cursor`, oldest first so a reader that
    /// pages forward never skips any, with what it needs to page on: the id to
    /// pass next, and how many events left the window before it asked.
    ///
    /// A cursor this run never issued (from a previous agent run) starts over
    /// rather than waiting for the new ids to catch up with it. `epoch` is the
    /// run the reader's cursor came from, when it says: ids restart at 1 every
    /// run, so a cursor from an older run that is *behind* this run's ids looks
    /// like one of ours, and only the epoch tells them apart. Without it the
    /// reader would page on from the middle of a run it never saw the start of.
    /// A reader that does not send one (it predates epochs) is judged by the id
    /// alone, which catches only the cursor that ran past this run's ids.
    pub fn since(&self, cursor: u64, epoch: Option<u64>, limit: usize) -> Value {
        let restarted = epoch.is_some_and(|epoch| epoch != self.epoch) || cursor >= self.next_id;
        let cursor = if restarted { 0 } else { cursor };
        let oldest = self.oldest_id();
        // Ids in (cursor, oldest) were evicted before this reader saw them.
        let missed = oldest.saturating_sub(cursor + 1);
        let skip = cursor.saturating_sub(oldest - 1) as usize;
        let events: Vec<&Value> = self.events.iter().skip(skip).take(limit).collect();
        let last = events
            .last()
            .and_then(|event| event["id"].as_u64())
            .unwrap_or(cursor.max(oldest - 1));
        json!({"epoch":self.epoch,"events":events,"cursor":last,
            "oldest_event_id":(!self.events.is_empty()).then_some(oldest),
            "next_event_id":self.next_id,"missed":missed,"restarted":restarted})
    }

    /// The newest `limit` events, oldest of them first. For a one-off look
    /// (`show firewall events`): it consumes nothing.
    pub fn tail(&self, limit: usize) -> impl Iterator<Item = &Value> {
        self.events
            .iter()
            .skip(self.events.len().saturating_sub(limit))
    }

    /// The pre-cursor `packet-events [limit]`: each event once, shared by every
    /// client that still speaks it, exactly as the ring behaved for them — but
    /// no longer at the expense of a cursor reader.
    pub fn legacy(&mut self, limit: usize) -> Vec<Value> {
        let page = self.since(self.legacy_cursor, Some(self.epoch), limit);
        self.legacy_cursor = page["cursor"].as_u64().unwrap_or(self.legacy_cursor);
        match page {
            Value::Object(mut page) => match page.remove("events") {
                Some(Value::Array(events)) => events,
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_of(n: u64, capacity: usize) -> PacketEventLog {
        let mut log = PacketEventLog::with_capacity(7, capacity);
        for n in 0..n {
            log.push(json!({"n":n}));
        }
        log
    }
    fn ids(page: &Value) -> Vec<u64> {
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_u64().unwrap())
            .collect()
    }

    #[test]
    fn readers_with_their_own_cursors_never_take_each_others_events() {
        let mut log = log_of(5, 16);
        let console = log.since(0, None, 100);
        assert_eq!(ids(&console), [1, 2, 3, 4, 5]);
        // A second reader — and the legacy one — still see every event.
        assert_eq!(ids(&log.since(0, None, 100)), [1, 2, 3, 4, 5]);
        assert_eq!(log.legacy(100).len(), 5);
        assert_eq!(ids(&log.since(0, None, 100)), [1, 2, 3, 4, 5]);
        // Paging forward from the returned cursor yields only what is new.
        log.push(json!({"n":5}));
        let next = log.since(console["cursor"].as_u64().unwrap(), Some(7), 100);
        assert_eq!(ids(&next), [6]);
        assert_eq!(next["missed"], 0);
        assert_eq!(next["epoch"], 7);
        // The legacy client keeps its once-only semantics.
        assert_eq!(log.legacy(100).len(), 1);
        assert!(log.legacy(100).is_empty());
    }

    #[test]
    fn a_reader_that_fell_out_of_the_window_is_told_how_many_it_missed() {
        let log = log_of(10, 4);
        let page = log.since(2, None, 100);
        assert_eq!(ids(&page), [7, 8, 9, 10]);
        assert_eq!(page["missed"], 4, "ids 3..=6 were evicted unseen");
        assert_eq!(page["oldest_event_id"], 7);
        assert_eq!(page["next_event_id"], 11);
        // A limited page keeps its place and reports no gap on the next one.
        let first = log.since(6, None, 2);
        assert_eq!(ids(&first), [7, 8]);
        let second = log.since(first["cursor"].as_u64().unwrap(), None, 2);
        assert_eq!(
            (ids(&second), second["missed"].clone()),
            (vec![9, 10], json!(0))
        );
        // Nothing new: the cursor stays where it was.
        let idle = log.since(10, None, 100);
        assert!(ids(&idle).is_empty());
        assert_eq!(idle["cursor"], 10);
    }

    #[test]
    fn a_cursor_from_a_previous_agent_run_starts_over() {
        let log = log_of(3, 16);
        let page = log.since(900, None, 100);
        assert_eq!(page["restarted"], true);
        assert_eq!(ids(&page), [1, 2, 3]);
        let empty = PacketEventLog::with_capacity(1, 4).since(0, None, 10);
        assert_eq!(empty["cursor"], 0);
        assert_eq!(empty["oldest_event_id"], Value::Null);
    }

    /// A cursor from the previous run that is still behind this run's ids:
    /// the id alone cannot tell it from one of ours, so without the epoch the
    /// reader silently skipped the new run's first events.
    #[test]
    fn an_older_cursor_from_a_previous_run_starts_over_by_its_epoch() {
        let log = log_of(10, 16);
        let page = log.since(4, Some(6), 100);
        assert_eq!(page["restarted"], true);
        assert_eq!(ids(&page), (1..=10).collect::<Vec<_>>());
        assert_eq!(page["missed"], 0, "nothing of this run was lost to it");
        let ours = log.since(4, Some(7), 100);
        assert_eq!(ours["restarted"], false);
        assert_eq!(ids(&ours), [5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn tail_is_the_newest_events_and_consumes_nothing() {
        let log = log_of(6, 16);
        let tail: Vec<_> = log.tail(2).map(|e| e["id"].as_u64().unwrap()).collect();
        assert_eq!(tail, [5, 6]);
        assert_eq!(ids(&log.since(0, None, 100)).len(), 6);
    }
}
