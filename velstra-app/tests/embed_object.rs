#[path = "../build_support/embed.rs"]
mod object;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "velstra-embed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn read_only_inputs_and_existing_outputs_can_be_replaced_repeatedly() {
    let dir = Directory::new();
    let input = dir.0.join("input");
    let output = dir.0.join("output");
    fs::write(&input, b"first object").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o444)).unwrap();
    fs::write(&output, b"previous build").unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o444)).unwrap();
    object::embed(&input, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"first object");
    assert_ne!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o200,
        0
    );
    fs::remove_file(&input).unwrap();
    fs::write(&input, b"second object").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o444)).unwrap();
    object::embed(&input, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"second object");
}
#[test]
fn missing_input_preserves_the_previous_build() {
    let dir = Directory::new();
    let output = dir.0.join("output");
    fs::write(&output, b"previous build").unwrap();
    assert!(object::embed(&dir.0.join("missing"), &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"previous build");
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}
#[test]
fn failed_read_does_not_publish_a_partial_object_or_leave_a_temporary() {
    let dir = Directory::new();
    let input = dir.0.join("directory");
    fs::create_dir(&input).unwrap();
    let output = dir.0.join("output");
    fs::write(&output, b"previous build").unwrap();
    assert!(object::embed(&input, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"previous build");
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
}
#[test]
fn concurrent_publishers_leave_one_complete_object() {
    let dir = Directory::new();
    let output = dir.0.join("output");
    let inputs: Vec<_> = (0..16u8)
        .map(|id| {
            let path = dir.0.join(format!("input-{id}"));
            fs::write(&path, vec![id; 65536]).unwrap();
            path
        })
        .collect();
    std::thread::scope(|scope| {
        for input in &inputs {
            let output = &output;
            scope.spawn(move || object::embed(input, output).unwrap());
        }
    });
    let bytes = fs::read(&output).unwrap();
    assert_eq!(bytes.len(), 65536);
    assert!(bytes.iter().all(|b| *b == bytes[0]));
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 17);
}
