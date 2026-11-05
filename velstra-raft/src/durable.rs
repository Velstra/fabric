//! One durable replacement boundary for both the Raft WAL and snapshots.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

trait FileOps {
    fn create(&self, path: &Path) -> io::Result<File>;
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()>;
    fn sync(&self, file: &File) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn directory(&self, path: &Path) -> io::Result<File>;
}

struct Filesystem;

impl FileOps for Filesystem {
    fn create(&self, path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }
    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
    fn directory(&self, path: &Path) -> io::Result<File> {
        File::open(path)
    }
}

pub(super) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_with(&Filesystem, path, bytes)
}

fn replace_with(ops: &impl FileOps, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("durable file has no parent"))?;
    let (temporary, mut file) = loop {
        let temporary = parent.join(format!(
            ".raft-write-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match ops.create(&temporary) {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = (|| {
        ops.write(&mut file, bytes)?;
        ops.sync(&file)?;
        ops.rename(&temporary, path)?;
        let directory = ops.directory(parent)?;
        ops.sync(&directory)
    })();
    // After rename the temp name is absent. Never remove/revert the final file:
    // a directory-sync failure means durability is unknown, not that the new
    // state is absent. Propagate failure; Raft must withhold acknowledgement.
    let _ = std::fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct FaultIo {
        fail: &'static str,
        steps: RefCell<Vec<&'static str>>,
    }
    impl FaultIo {
        fn step(&self, name: &'static str) -> io::Result<()> {
            self.steps.borrow_mut().push(name);
            if self.fail == name {
                Err(io::Error::other(format!("injected {name} failure")))
            } else {
                Ok(())
            }
        }
    }
    impl FileOps for FaultIo {
        fn create(&self, path: &Path) -> io::Result<File> {
            self.step("create")?;
            Filesystem.create(path)
        }
        fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
            self.step("write")?;
            Filesystem.write(file, bytes)
        }
        fn sync(&self, file: &File) -> io::Result<()> {
            self.step(if file.metadata()?.is_dir() {
                "directory-sync"
            } else {
                "file-sync"
            })?;
            Filesystem.sync(file)
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.step("rename")?;
            Filesystem.rename(from, to)
        }
        fn directory(&self, path: &Path) -> io::Result<File> {
            self.step("directory-open")?;
            Filesystem.directory(path)
        }
    }

    #[test]
    fn every_persistence_boundary_is_ordered_and_its_failure_is_propagated() {
        let directory = std::env::temp_dir().join(format!(
            "velstra-raft-durability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("state.json");
        let stages = [
            "create",
            "write",
            "file-sync",
            "rename",
            "directory-open",
            "directory-sync",
        ];
        for (index, stage) in stages.iter().enumerate() {
            std::fs::write(&path, b"old complete state").unwrap();
            let ops = FaultIo {
                fail: stage,
                steps: RefCell::new(Vec::new()),
            };
            let error = replace_with(&ops, &path, b"new complete state").unwrap_err();
            assert!(error.to_string().contains(stage));
            assert_eq!(*ops.steps.borrow(), stages[..=index]);
            let bytes = std::fs::read(&path).unwrap();
            if index <= 3 {
                assert_eq!(bytes, b"old complete state");
            } else {
                assert_eq!(bytes, b"new complete state");
            }
            assert_eq!(
                std::fs::read_dir(&directory).unwrap().count(),
                1,
                "no unclaimed partial temp file"
            );
        }
        let ops = FaultIo {
            fail: "none",
            steps: RefCell::new(Vec::new()),
        };
        replace_with(&ops, &path, b"durably committed").unwrap();
        assert_eq!(*ops.steps.borrow(), stages);
        assert_eq!(std::fs::read(&path).unwrap(), b"durably committed");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
