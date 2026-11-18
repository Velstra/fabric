//! Explicit outcomes for ordered state publication, not a transaction protocol.
//!
//! Two successful helper calls do not make a pair atomic. A first write can
//! remain visible when the second fails, and either entry can subsequently be
//! replaced or evicted. In particular, deleting a key after failure is not safe
//! rollback: another writer may already own the entry under that key.

/// What this publication attempt did, not proof of current map contents.
#[must_use = "state publication failures must be handled explicitly"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatePublication {
    /// No publication attempted; this does not prove that a pair exists.
    /// Separate best-effort reset deletion may still have run.
    NoChange,
    /// Both helpers reported success, not persistence or LRU retention.
    Written,
    /// A helper failed. An earlier successful write may remain visible.
    Failed,
}

impl StatePublication {
    /// Whether this attempt encountered a publication failure.
    ///
    /// `false` for `NoChange` is not evidence that state exists or is complete.
    #[inline(always)]
    pub const fn failed(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// Attempt two writes in order, stopping immediately if the first fails.
///
/// Returns `Written` only when both helpers return `true`; otherwise returns
/// `Failed`. This helper never returns `NoChange` and never attempts rollback.
/// It provides neither atomic visibility nor a guarantee against subsequent
/// deletion, replacement or LRU eviction. Callers still need a separate state
/// ownership/admission protocol; rollback by deleting keys is not such a
/// protocol because it can remove another writer's entry.
#[inline(always)]
pub fn publish_state_pair(
    first: impl FnOnce() -> bool,
    second: impl FnOnce() -> bool,
) -> StatePublication {
    if !first() || !second() {
        StatePublication::Failed
    } else {
        StatePublication::Written
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    #[test]
    fn only_failed_outcome_reports_failure() {
        assert!(!StatePublication::NoChange.failed());
        assert!(!StatePublication::Written.failed());
        assert!(StatePublication::Failed.failed());
    }

    #[test]
    fn every_combination_has_an_explicit_ordered_outcome() {
        for first_result in [false, true] {
            for second_result in [false, true] {
                let calls = RefCell::new(Vec::new());
                let outcome = publish_state_pair(
                    || {
                        calls.borrow_mut().push("first");
                        first_result
                    },
                    || {
                        calls.borrow_mut().push("second");
                        second_result
                    },
                );
                assert_eq!(
                    outcome,
                    if first_result && second_result {
                        StatePublication::Written
                    } else {
                        StatePublication::Failed
                    }
                );
                assert_ne!(outcome, StatePublication::NoChange);
                assert_eq!(
                    *calls.borrow(),
                    if first_result {
                        vec!["first", "second"]
                    } else {
                        vec!["first"]
                    }
                );
            }
        }
    }

    #[test]
    fn failed_first_write_never_invokes_second() {
        let outcome = publish_state_pair(|| false, || panic!("second must not run"));
        assert_eq!(outcome, StatePublication::Failed);
    }

    #[test]
    fn second_failure_does_not_undo_first_side_effect() {
        let first_visible = Cell::new(false);
        let outcome = publish_state_pair(
            || {
                first_visible.set(true);
                true
            },
            || {
                assert!(first_visible.get());
                false
            },
        );
        assert!(outcome.failed());
        assert!(first_visible.get(), "no rollback or atomicity is provided");
    }

    #[test]
    fn callbacks_can_consume_owned_state_once() {
        let first = String::from("first");
        let second = String::from("second");
        let outcome = publish_state_pair(
            move || {
                drop(first);
                true
            },
            move || {
                drop(second);
                true
            },
        );
        assert_eq!(outcome, StatePublication::Written);
    }
}
