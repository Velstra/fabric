//! Publish a complete embedded object without inheriting read-only source modes.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

struct Temporary {
    path: PathBuf,
    pending: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.pending {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn embed(source: &Path, destination: &Path) -> io::Result<()> {
    // Open before reserving a temporary: a missing input must not disturb the
    // previous successful output. Cargo serialises this OUT_DIR, but distinct
    // names also protect concurrent callers and stale files after a crash.
    let mut input = File::open(source)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("object output has no parent"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| io::Error::other("object output has no name"))?;
    for sequence in 0..1024 {
        let path = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        let mut output = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let mut temporary = Temporary {
            path,
            pending: true,
        };
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        // rename replaces an existing read-only destination without opening it
        // for writing. A failed copy never publishes a truncated object.
        fs::rename(&temporary.path, destination)?;
        // Disarm before dropping: another writer can already have reserved
        // this same name after rename removed it. Never unlink that new file.
        temporary.pending = false;
        return Ok(());
    }
    Err(io::Error::other("no free temporary object path"))
}
