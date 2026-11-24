//! Running the agent's eBPF program loads on several threads at once.
//!
//! Loading a program is the kernel verifier walking it, and that walk is most
//! of an agent start: about 3 s of a 4 s start on 6.12 and 4–5 s of a 5–6 s
//! start on 6.18 (2 vCPUs, the same object). A privileged load holds no lock
//! shared with other loads, so the programs of one object verify concurrently.
//! Only the loading moves here; the callers still fill the program arrays and
//! attach the hooks one at a time, in their own order.
//!
//! This module holds the scheduling, which needs no kernel: how many threads,
//! which program starts first, and a bounded pool that returns its results in
//! the order it was given them.

use std::{
    num::NonZeroUsize,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Never more than this many verifications at once. Each holds its program's
/// verifier state in kernel memory, and past four the start gains nothing: the
/// longest program alone takes about as long as the rest shared out over four.
pub(crate) const MAX_LOAD_THREADS: usize = 4;

/// The programs that take longest to verify, longest first (measured on
/// 6.18.65: masquerade 1.5 s, IPv4 state admission 1.4 s, IPv6 egress 1.3 s,
/// related egress 0.9 s and 0.5 s; nothing else above 0.3 s). Starting them
/// first keeps one of them from being the last thing still running.
pub(crate) const LONGEST_FIRST: &[&str] = &[
    "velstra_masquerade",
    "velstra_v4_state",
    "velstra_egress_v6",
    "velstra_related_egress",
    "velstra_related_egress_apply",
];

/// How many threads load `jobs` programs: the CPUs this process may run on,
/// at most [`MAX_LOAD_THREADS`], never more than there are jobs, at least one.
pub(crate) fn thread_count(available: Option<NonZeroUsize>, jobs: usize) -> usize {
    available
        .map_or(1, NonZeroUsize::get)
        .min(MAX_LOAD_THREADS)
        .min(jobs)
        .max(1)
}

/// The indices of `names` in the order their loads start: the names in
/// [`LONGEST_FIRST`], in that order, then the rest as given.
pub(crate) fn start_order(names: &[&str]) -> Vec<usize> {
    let long = LONGEST_FIRST
        .iter()
        .filter_map(|long| names.iter().position(|name| name == long));
    let rest = (0..names.len()).filter(|&i| !LONGEST_FIRST.contains(&names[i]));
    long.chain(rest).collect()
}

/// Runs `job` on every item, on at most `threads` threads (the calling thread
/// is one of them), starting the items in `order`, a permutation of their
/// indices. The results come back in the order of `items`, whatever order the
/// jobs finished in. A thread that cannot be spawned only means fewer threads.
pub(crate) fn run_bounded<T: Send, R: Send>(
    items: Vec<T>,
    order: &[usize],
    threads: usize,
    job: impl Fn(T) -> R + Sync,
) -> Vec<R> {
    debug_assert_eq!(order.len(), items.len(), "order must name every item once");
    let slots: Vec<Mutex<Option<T>>> = items
        .into_iter()
        .map(|item| Mutex::new(Some(item)))
        .collect();
    let results: Vec<Mutex<Option<R>>> = slots.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let work = || {
        while let Some(&index) = order.get(next.fetch_add(1, Ordering::Relaxed)) {
            let item = slots[index]
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .expect("order names every item once");
            let result = job(item);
            *results[index]
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(result);
        }
    };
    std::thread::scope(|scope| {
        for n in 1..threads.min(order.len()) {
            let spawned = std::thread::Builder::new()
                .name(format!("ebpf-load-{n}"))
                .spawn_scoped(scope, work);
            if spawned.is_err() {
                break;
            }
        }
        work();
    });
    results
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .expect("every item ran")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Duration,
    };

    use super::*;

    fn cpus(n: usize) -> Option<NonZeroUsize> {
        NonZeroUsize::new(n)
    }

    #[test]
    fn thread_count_follows_the_cpus_up_to_the_cap() {
        assert_eq!(thread_count(cpus(1), 21), 1);
        assert_eq!(thread_count(cpus(2), 21), 2);
        assert_eq!(thread_count(cpus(4), 21), 4);
        assert_eq!(thread_count(cpus(64), 21), MAX_LOAD_THREADS);
    }

    #[test]
    fn thread_count_is_one_when_the_cpus_are_unknown() {
        assert_eq!(thread_count(None, 21), 1);
    }

    #[test]
    fn thread_count_never_exceeds_the_jobs_and_is_never_zero() {
        assert_eq!(thread_count(cpus(4), 2), 2);
        assert_eq!(thread_count(cpus(4), 0), 1);
    }

    #[test]
    fn start_order_puts_the_longest_first_and_keeps_the_rest_in_place() {
        let names = [
            "velstra_forward",
            "velstra_v4_state",
            "velstra_main",
            "velstra_masquerade",
            "velstra_egress",
        ];
        // masquerade, v4_state, then forward, main, egress as given.
        assert_eq!(start_order(&names), vec![3, 1, 0, 2, 4]);
    }

    #[test]
    fn start_order_is_a_permutation_without_any_long_program() {
        assert_eq!(start_order(&["a", "b", "c"]), vec![0, 1, 2]);
        assert!(start_order(&[]).is_empty());
    }

    #[test]
    fn run_bounded_returns_results_in_item_order_whatever_finishes_first() {
        // The first item takes longest, so on 3 threads it finishes last.
        let items = vec![30u64, 1, 2, 3, 4];
        let order: Vec<usize> = (0..items.len()).collect();
        let out = run_bounded(items, &order, 3, |ms| {
            thread::sleep(Duration::from_millis(ms));
            ms * 10
        });
        assert_eq!(out, vec![300, 10, 20, 30, 40]);
    }

    #[test]
    fn run_bounded_never_runs_more_than_threads_jobs_at_once() {
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let items: Vec<usize> = (0..12).collect();
        let order: Vec<usize> = (0..items.len()).collect();
        let out = run_bounded(items, &order, 3, |i| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(15));
            running.fetch_sub(1, Ordering::SeqCst);
            i
        });
        assert_eq!(out, (0..12).collect::<Vec<_>>());
        // Never above the bound; and with 12 jobs of 15 ms, more than one thread
        // must have run at once, or the pool did not run in parallel at all.
        let peak = peak.load(Ordering::SeqCst);
        assert!((2..=3).contains(&peak), "peak concurrency {peak}, bound 3");
    }

    #[test]
    fn run_bounded_starts_the_items_in_the_given_order() {
        let started = Mutex::new(Vec::new());
        let items = vec!['a', 'b', 'c', 'd'];
        run_bounded(items, &[2, 0, 3, 1], 1, |c| started.lock().unwrap().push(c));
        assert_eq!(started.into_inner().unwrap(), vec!['c', 'a', 'd', 'b']);
    }

    #[test]
    fn run_bounded_on_one_thread_stays_on_the_calling_thread() {
        let caller = thread::current().id();
        let items = vec![(); 5];
        let order: Vec<usize> = (0..items.len()).collect();
        let ids = run_bounded(items, &order, 1, |()| thread::current().id());
        assert!(ids.iter().all(|id| *id == caller));
    }

    #[test]
    fn run_bounded_handles_no_items() {
        let out: Vec<u8> = run_bounded(Vec::<u8>::new(), &[], 4, |x| x);
        assert!(out.is_empty());
    }

    #[test]
    fn run_bounded_moves_non_copy_items_and_results() {
        let items = vec![String::from("x"), String::from("yy")];
        let out = run_bounded(items, &[1, 0], 2, |s| s.len());
        assert_eq!(out, vec![1, 2]);
    }
}
