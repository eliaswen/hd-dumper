//! The library API end to end. Needs a real APK: `HD_APK=/path/to/hayday.apk`
//! (Hay Day build 1598); skipped when unset.

use std::path::PathBuf;

use hd_dumper::progress::Progress;
use hd_dumper::{Options, Source};

#[derive(Default)]
struct Recorder {
    messages: Vec<String>,
    entries: usize,
}

impl Progress for Recorder {
    fn message(&mut self, message: &str) {
        self.messages.push(message.to_string());
    }
    fn entry(&mut self, _done: usize, _total: usize, _name: &str) {
        self.entries += 1;
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hd-dumper-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn builtin_copies_match_the_repository_files() {
    let Some(apk) = std::env::var_os("HD_APK").map(PathBuf::from) else {
        eprintln!("HD_APK not set; skipping");
        return;
    };
    let builtin = scratch("builtin");
    let from_disk = scratch("disk");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut progress = Recorder::default();
    let mut options = Options::new(&apk, &builtin);
    options.spec = Source::Builtin;
    options.shipped = Source::Builtin;
    options.require_complete = true;
    let summary = hd_dumper::dump(&options, &mut progress).unwrap();
    assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
    assert_eq!(summary.files.len(), 14);
    assert_eq!(
        summary.shipped.as_deref().unwrap(),
        ["command-schema.json", "command-evidence.json"]
    );
    assert!(summary.spec.as_ref().unwrap().starts_with("(built-in)"));
    assert!(
        progress.entries > 100,
        "{} entry callbacks",
        progress.entries
    );
    assert!(progress.messages.iter().any(|m| m.contains("writing")));

    options.out = from_disk.clone();
    options.spec = Source::Path(root.join("client-spec.toml"));
    options.shipped = Source::Path(root.join("shipped"));
    hd_dumper::dump(&options, &mut hd_dumper::progress::Silent).unwrap();

    // Identical trees, apart from the spec's name in sources.json.
    for file in &summary.files {
        let a =
            std::fs::read(file.path.split('/').fold(builtin.clone(), |p, c| p.join(c))).unwrap();
        let b = std::fs::read(
            file.path
                .split('/')
                .fold(from_disk.clone(), |p, c| p.join(c)),
        )
        .unwrap();
        if file.path == "sources.json" {
            continue;
        }
        assert!(
            a == b,
            "{} differs between built-in and on-disk inputs",
            file.path
        );
    }

    // Without a spec, the two spec-driven outputs are reported, not written,
    // and require_complete refuses before writing anything.
    let skipped = scratch("skip");
    options.out = skipped.clone();
    options.spec = Source::Skip;
    assert!(hd_dumper::dump(&options, &mut hd_dumper::progress::Silent).is_err());
    assert!(!skipped.exists());
    options.require_complete = false;
    let partial = hd_dumper::dump(&options, &mut hd_dumper::progress::Silent).unwrap();
    let names: Vec<&str> = partial.skipped.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(names, ["order-resources.json", "starter/layout.json"]);

    for dir in [builtin, from_disk, skipped] {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn missing_apk_is_an_error() {
    let options = Options::new("does-not-exist.apk", scratch("missing"));
    let error = hd_dumper::dump(&options, &mut hd_dumper::progress::Silent).unwrap_err();
    assert!(error.to_string().contains("does not exist"));
}
