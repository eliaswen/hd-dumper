//! Extract the runtime resource tables that `hd-server` loads from a Hay Day APK.
//!
//! The library behind the `hd-dumper` CLI, also used by apps that run the
//! dump on the device itself. The client spec and the two shipped protocol
//! tables are compiled in, so no files have to sit beside the program.
//!
//! - [`dump`]: the whole job, from an APK to a resource directory.
//! - [`progress`]: progress callbacks ([`progress::Console`] for terminals).
//!
//! Internally:
//! - `apk`: the APK's zip directory, read without unpacking.
//! - `data`: the `assets/data` CSVs and the rule that finds the tables in them.
//! - `dump`: turns those tables into the files `hd-server` reads.
//! - `native`: the client's data-type registry, scanned out of `libg.so`.
//! - `spec`: the client facts an APK's data tables do not contain.
//!
//! Nothing is read from the network and nothing is unpacked to disk. Two files
//! the server needs describe the wire protocol rather than the data, so they
//! ship with this tool; everything else is derived from the APK the caller
//! supplies, and `sources.json` records what came from where.

mod apk;
mod data;
mod dump;
mod native;
pub mod progress;
mod spec;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use progress::Progress;

/// Where a file that ships with the tool comes from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Source {
    /// An installed copy if one is found (the working directory, next to the
    /// executable, or `../share/hd-dumper` beside it), else the built-in one.
    #[default]
    Default,
    /// The copy compiled into the tool.
    Builtin,
    /// This file or directory. A path that does not exist skips the outputs
    /// that need it; the summary says so.
    Path(PathBuf),
    /// None: skip the outputs that need it.
    Skip,
}

/// What [`dump`] reads and where it writes.
#[derive(Debug, Clone)]
pub struct Options {
    /// Input APK (Hay Day 1.43.150 build 1598, x86 or arm64-v8a).
    pub apk: PathBuf,
    /// Output resource directory, the server's `resources_dir`.
    pub out: PathBuf,
    /// The client spec (`client-spec.toml`).
    pub spec: Source,
    /// The directory of the two shipped command tables.
    pub shipped: Source,
    /// Data-type registry as JSON, for APKs with no `libg.so` to scan.
    pub type_map: Option<PathBuf>,
    /// Fail when any resource file could not be produced.
    pub require_complete: bool,
}

impl Options {
    /// Defaults for everything but the input and output.
    pub fn new(apk: impl Into<PathBuf>, out: impl Into<PathBuf>) -> Self {
        Self {
            apk: apk.into(),
            out: out.into(),
            spec: Source::Default,
            shipped: Source::Default,
            type_map: None,
            require_complete: false,
        }
    }
}

/// A resource file [`dump`] wrote.
#[derive(Debug, Clone)]
pub struct Written {
    /// Path relative to the output directory, `/`-separated.
    pub path: String,
    pub bytes: usize,
    /// One line of provenance.
    pub note: String,
}

/// What [`dump`] did.
#[derive(Debug, Clone)]
pub struct Summary {
    pub apk_sha256: String,
    /// The spec used and what it holds, or why there was none.
    pub spec: std::result::Result<String, String>,
    /// The shipped tables copied, or why there were none.
    pub shipped: std::result::Result<Vec<&'static str>, String>,
    /// `(zip entry, sha256)` of every `libg.so` in the APK.
    pub libraries: Vec<(String, String)>,
    pub stats: Vec<String>,
    pub files: Vec<Written>,
    /// Files that could not be produced, with the reason.
    pub skipped: Vec<(String, String)>,
}

/// Read `options.apk` and write the resource tree to `options.out`.
pub fn dump(options: &Options, progress: &mut dyn Progress) -> Result<Summary> {
    if !options.apk.is_file() {
        bail!("input APK does not exist: {}", options.apk.display());
    }
    let (spec, spec_missing) = match resolve(&options.spec, "client-spec.toml") {
        Resolved::Builtin => (Some(spec::Spec::bundled()?), None),
        Resolved::Path(path) if path.exists() => (Some(spec::Spec::load(&path)?), None),
        Resolved::Path(path) => (None, Some(format!("{} does not exist", path.display()))),
        Resolved::Skip => (None, Some("skipped".to_string())),
    };
    let (shipped, shipped_missing) = match resolve(&options.shipped, "shipped") {
        Resolved::Builtin => (Some(native::shipped_bundled()?), None),
        Resolved::Path(path) if path.exists() => (Some(native::shipped(&path)?), None),
        Resolved::Path(path) => (None, Some(format!("{} does not exist", path.display()))),
        Resolved::Skip => (None, Some("skipped".to_string())),
    };

    progress.message(&format!(
        "Hashing and opening {} ...",
        options.apk.display()
    ));
    let mut apk = apk::Archive::open(&options.apk)?;
    let inputs = data::Inputs::read(&mut apk, progress)?;

    // The registry is scanned from the x86 library, or the arm64-v8a one when
    // there is no x86 build; an APK that ships neither needs a type map.
    progress.message(&format!(
        "Parsed {} CSVs ({} data tables) and {} JSON documents",
        inputs.csvs.len(),
        inputs.tables.len(),
        inputs.documents.len()
    ));
    let types = match &options.type_map {
        Some(path) => Some(native::TypeMap::load(path)?),
        None => {
            progress.message("Scanning libg.so for the data-type registry ...");
            match scannable_library(&mut apk, &inputs)? {
                Some((entry, libg)) => Some(native::TypeMap::scan(&libg).with_context(|| {
                    format!(
                        "the binder scan of {entry} failed; \
                         pass --type-map to supply the data-type registry instead"
                    )
                })?),
                None => None,
            }
        }
    };

    let sources = dump::Sources {
        inputs: &inputs,
        spec: spec.as_ref(),
        types: types.as_ref(),
        shipped,
    };
    progress.message("Building resource files ...");
    let plan = dump::Plan::build(&sources)?;

    if options.require_complete && !plan.skipped.is_empty() {
        bail!(
            "{} resource files could not be produced ({}); rerun without --require-complete to accept a partial tree",
            plan.skipped.len(),
            plan.skipped
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let count = plan.files.len();
    for (index, file) in plan.files.iter().enumerate() {
        progress.message(&format!("[{}/{count}] writing {}", index + 1, file.path));
        let path = file
            .path
            .split('/')
            .fold(options.out.clone(), |path, part| path.join(part));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, &file.bytes)
            .with_context(|| format!("writing {}", path.display()))?;
    }

    Ok(Summary {
        apk_sha256: apk.sha256().to_string(),
        spec: match &spec {
            Some(spec) => Ok(format!(
                "{} ({} walked tables, {} layout types, money_type {})",
                spec.path.display(),
                spec.walk.len(),
                spec.layout_types.len(),
                spec.money_type
                    .map(|kind| kind.to_string())
                    .unwrap_or_else(|| "derived".to_string())
            )),
            None => Err(spec_missing.unwrap_or_default()),
        },
        shipped: if plan.shipped.is_empty() {
            Err(shipped_missing.unwrap_or_else(|| "none".to_string()))
        } else {
            Ok(plan.shipped.clone())
        },
        libraries: inputs
            .libraries
            .iter()
            .map(|library| (library.entry.clone(), library.sha256.clone()))
            .collect(),
        stats: plan.stats.clone(),
        files: plan
            .files
            .iter()
            .map(|file| Written {
                path: file.path.clone(),
                bytes: file.bytes.len(),
                note: file.note.clone(),
            })
            .collect(),
        skipped: plan.skipped.clone(),
    })
}

enum Resolved {
    Builtin,
    Path(PathBuf),
    Skip,
}

fn resolve(source: &Source, name: &str) -> Resolved {
    match source {
        Source::Default => installed(name).map_or(Resolved::Builtin, Resolved::Path),
        Source::Builtin => Resolved::Builtin,
        Source::Path(path) => Resolved::Path(path.clone()),
        Source::Skip => Resolved::Skip,
    }
}

/// An installed copy of a file that ships with the tool: in the working
/// directory, next to the executable (a release archive), or in
/// `../share/hd-dumper` beside it (a system package installing
/// `/usr/bin/hd-dumper`).
fn installed(name: &str) -> Option<PathBuf> {
    let local = PathBuf::from(name);
    if local.exists() {
        return Some(local);
    }
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    [
        dir.join(name),
        dir.join("..").join("share").join("hd-dumper").join(name),
    ]
    .into_iter()
    .find(|candidate| candidate.exists())
}

/// The ABIs the registry scan reads, in the order it prefers them.
const SCANNED_ABIS: [&str; 2] = ["x86", "arm64-v8a"];

/// The `libg.so` to scan for the registry, with its zip entry: the x86 build
/// when the APK has one, otherwise the arm64-v8a build.
fn scannable_library(
    archive: &mut apk::Archive,
    inputs: &data::Inputs,
) -> Result<Option<(String, Vec<u8>)>> {
    for abi in SCANNED_ABIS {
        if let Some(library) = inputs.libraries.iter().find(|library| library.abi == abi) {
            return Ok(Some((library.entry.clone(), archive.read(&library.entry)?)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file<'a>(plan: &'a dump::Plan, name: &str) -> &'a dump::File {
        plan.files
            .iter()
            .find(|file| file.path == name)
            .unwrap_or_else(|| panic!("no {name} in the plan"))
    }

    /// End-to-end check against a real APK:
    /// `HD_APK=/path/to/hayday.apk cargo test -- --ignored`.
    #[test]
    #[ignore = "needs a real APK via HD_APK"]
    fn generated_tree_matches_the_server_contract() {
        let path = std::env::var_os("HD_APK").expect("set HD_APK to a Hay Day build-1598 APK");
        let mut archive = apk::Archive::open(std::path::Path::new(&path)).unwrap();
        let inputs = data::Inputs::read(&mut archive, &mut progress::Silent).unwrap();
        let spec = spec::Spec::load(std::path::Path::new("client-spec.toml")).ok();
        let (entry, libg) = scannable_library(&mut archive, &inputs)
            .unwrap()
            .expect("the APK has no x86 or arm64-v8a libg.so");
        let types = Some(native::TypeMap::scan(&libg).unwrap());
        let count = types.as_ref().unwrap().tables.len();
        if entry == "lib/x86/libg.so" {
            // Measured for build 1598: 226 binder calls resolve to 225 tables.
            assert_eq!(count, 225);
        } else {
            assert!(count > 200, "{entry}: {count} tables");
        }
        let sources = dump::Sources {
            inputs: &inputs,
            spec: spec.as_ref(),
            types: types.as_ref(),
            shipped: None,
        };
        let plan = dump::Plan::build(&sources).unwrap();

        let levels = String::from_utf8(file(&plan, "exp-levels.csv").bytes.clone()).unwrap();
        let rows: Vec<&str> = levels.lines().skip(1).collect();
        assert!(rows.len() > 100, "{} levels", rows.len());
        for (index, row) in rows.iter().enumerate() {
            let (level, requirement) = row.split_once(',').expect("level,xp row");
            assert_eq!(level.parse::<usize>().unwrap(), index + 1);
            requirement.parse::<u32>().unwrap();
        }

        let tables: serde_json::Value =
            serde_json::from_slice(&file(&plan, "replay-tables.json").bytes).unwrap();
        let tables = tables.as_object().unwrap();
        assert!(tables.len() > 100, "{} tables", tables.len());
        // The progression reader indexes Level and GoodReward directly, so every
        // record of a table has to carry the table's whole column set.
        for row in tables["exp_levels"].as_array().unwrap() {
            for column in ["Level", "ExpToNextLevel", "GoodReward", "GoodAmount"] {
                assert!(row.get(column).is_some(), "exp_levels row lacks {column}");
            }
        }

        // Every type the registry names has to resolve to a table the replay
        // can open, otherwise a command touching it panics at login.
        let registry: serde_json::Value =
            serde_json::from_slice(&file(&plan, "replay-type-tables.json").bytes).unwrap();
        let registry = registry.as_object().unwrap();
        assert!(registry.len() > 200, "{} types", registry.len());
        for (kind, name) in registry {
            let name = name.as_str().unwrap();
            assert!(
                tables.contains_key(name),
                "type {kind} names unknown table {name}"
            );
        }

        // The starter resolves object names to IDs through these tables, so the
        // avatar's bitset types have to be among them.
        let starter: serde_json::Value =
            serde_json::from_slice(&file(&plan, "starter/tables.json").bytes).unwrap();
        let starter = starter.as_array().unwrap();
        assert!(starter.len() > 100, "{} starter tables", starter.len());
        let kinds: Vec<u64> = starter
            .iter()
            .map(|entry| entry["kind"].as_u64().unwrap())
            .collect();
        assert!(
            kinds.windows(2).all(|pair| pair[0] < pair[1]),
            "starter kinds are not ascending"
        );
        // A few builds ship tables with a header and no named rows; the rest are
        // what the starter resolves object names through.
        let with_rows = starter
            .iter()
            .filter(|entry| !entry["rows"].as_array().unwrap().is_empty())
            .count();
        assert!(
            with_rows * 10 > starter.len() * 9,
            "only {with_rows} of {} starter tables carry rows",
            starter.len()
        );

        let layout: serde_json::Value =
            serde_json::from_slice(&file(&plan, "starter/layout.json").bytes).unwrap();
        let layout = layout.as_array().unwrap();
        assert!(layout.len() > 20, "{} layout types", layout.len());
        for row in layout {
            let (named, words) = (row[2].as_u64().unwrap(), row[4].as_u64().unwrap());
            assert_eq!(words, named.div_ceil(32));
            assert!(
                kinds.contains(&row[0].as_u64().unwrap()),
                "layout type {} is missing from starter/tables.json",
                row[0]
            );
        }

        for document in ["starter/level_0.json", "starter/game_config.json"] {
            let records: Vec<Vec<String>> =
                serde_json::from_slice(&file(&plan, document).bytes).unwrap();
            assert!(!records.is_empty());
        }
        let config: serde_json::Value =
            serde_json::from_slice(&file(&plan, "replay-config.json").bytes).unwrap();
        assert!(!config.as_object().unwrap().is_empty());

        // Without a shipped directory the two command tables are reported, not
        // silently missing.
        for entry in native::SHIPPED {
            assert!(
                plan.skipped.iter().any(|(path, _)| path == entry.path),
                "{} was neither written nor reported",
                entry.path
            );
        }
    }
}

#[cfg(test)]
mod bundled_tests {
    /// The compiled-in copies parse and are the files in the repository.
    #[test]
    fn bundled_files_load() {
        let spec = crate::spec::Spec::bundled().unwrap();
        assert!(!spec.walk.is_empty());
        let shipped = crate::native::shipped_bundled().unwrap();
        let on_disk = crate::native::shipped(std::path::Path::new("shipped")).unwrap();
        assert_eq!(shipped.len(), on_disk.len());
        for (a, b) in shipped.iter().zip(&on_disk) {
            assert_eq!(a.2, b.2, "{}", a.0.name);
        }
    }
}
