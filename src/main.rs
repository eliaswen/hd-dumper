//! Extract the runtime resource tables that `hd-server` loads from a Hay Day APK.
//!
//! - [`apk`]: the APK's zip directory, read without unpacking.
//! - [`data`]: the `assets/data` CSVs and the rule that finds the tables in them.
//! - [`dump`]: turns those tables into the files `hd-server` reads.
//! - [`native`]: the client's data-type registry, scanned out of `libg.so`.
//! - [`spec`]: the client facts an APK's data tables do not contain.
//!
//! Nothing is read from the network and nothing is unpacked to disk. Two files
//! the server needs describe the wire protocol rather than the data, so they
//! ship with this tool ([`native::SHIPPED`]); everything else is derived from
//! the APK the caller supplies, and `sources.json` records what came from where.

mod apk;
mod data;
mod dump;
mod native;
mod spec;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "hd-dumper",
    about = "Extract the runtime resource tables hd-server needs from a Hay Day APK"
)]
struct Args {
    /// Input APK path (Hay Day 1.43.150 build 1598, x86 or arm64-v8a).
    #[arg(long)]
    apk: PathBuf,

    /// Output resource directory, the server's `resources_dir`.
    #[arg(long, short = 'o', default_value = "resources")]
    out: PathBuf,

    /// Client facts the APK's data tables do not contain: the order generator's
    /// table walk, the avatar's bitset types, and UnlockLevel cells the CSVs
    /// leave empty. Default: the `client-spec.toml` that ships with the tool.
    #[arg(long)]
    spec: Option<PathBuf>,

    /// The two command tables that ship with this tool, as a directory.
    /// Default: the bundled `shipped` directory.
    #[arg(long)]
    shipped: Option<PathBuf>,

    /// Data-type registry as JSON (`{"16": "animal_feed", ...}`), for APKs with
    /// no x86 or arm64-v8a `libg.so` to scan. The numbers are ABI-independent.
    #[arg(long)]
    type_map: Option<PathBuf>,

    /// Fail instead of reporting anything that could not be produced.
    #[arg(long)]
    require_complete: bool,
}

/// Locates a file that ships with the tool: in the working directory, next to
/// the executable (a release archive), or in `../share/hd-dumper` beside it (a
/// system package installing `/usr/bin/hd-dumper`). Falls back to the bare
/// relative path, so a missing file is reported under its usual name.
fn bundled(name: &str) -> PathBuf {
    let local = PathBuf::from(name);
    if local.exists() {
        return local;
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    if let Some(dir) = exe_dir {
        for candidate in [dir.join(name), dir.join("../share/hd-dumper").join(name)] {
            if candidate.exists() {
                return candidate;
            }
        }
    }
    local
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    let spec_path = args.spec.take().unwrap_or_else(|| bundled("client-spec.toml"));
    let shipped_path = args.shipped.take().unwrap_or_else(|| bundled("shipped"));
    if !args.apk.exists() {
        bail!("input APK does not exist: {}", args.apk.display());
    }
    let spec = if spec_path.exists() {
        Some(spec::Spec::load(&spec_path)?)
    } else {
        None
    };

    eprintln!("Hashing and opening {} ...", args.apk.display());
    let mut apk = apk::Archive::open(&args.apk)?;
    let inputs = data::Inputs::read(&mut apk)?;

    // The registry is scanned from the x86 library, or the arm64-v8a one when
    // there is no x86 build; an APK that ships neither needs `--type-map`.
    eprintln!(
        "Parsed {} CSVs ({} data tables) and {} JSON documents",
        inputs.csvs.len(),
        inputs.tables.len(),
        inputs.documents.len()
    );
    if args.type_map.is_none() {
        eprintln!("Scanning libg.so for the data-type registry ...");
    }
    let types = match &args.type_map {
        Some(path) => Some(native::TypeMap::load(path)?),
        None => match scannable_library(&mut apk, &inputs)? {
            Some((entry, libg)) => Some(native::TypeMap::scan(&libg).with_context(|| {
                format!(
                    "the binder scan of {entry} failed; \
                     pass --type-map to supply the data-type registry instead"
                )
            })?),
            None => None,
        },
    };

    let shipped = if shipped_path.exists() {
        Some(native::shipped(&shipped_path)?)
    } else {
        None
    };

    let sources = dump::Sources {
        inputs: &inputs,
        spec: spec.as_ref(),
        types: types.as_ref(),
        shipped,
    };
    eprintln!("Building resource files ...");
    let plan = dump::Plan::build(&sources)?;

    let count = plan.files.len();
    for (index, file) in plan.files.iter().enumerate() {
        eprintln!("[{}/{count}] writing {}", index + 1, file.path);
        let path = args.out.join(&file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &file.bytes)
            .map_err(|error| anyhow::anyhow!("writing {}: {error}", path.display()))?;
    }

    println!("APK: {} (sha256 {})", apk.path().display(), apk.sha256());
    match &spec {
        Some(spec) => println!(
            "  spec: {} ({} walked tables, {} layout types, money_type {})",
            spec.path.display(),
            spec.walk.len(),
            spec.layout_types.len(),
            spec.money_type
                .map(|kind| kind.to_string())
                .unwrap_or_else(|| "derived".to_string())
        ),
        None => println!(
            "  spec: none ({} does not exist; order-resources.json and starter/layout.json will be skipped)",
            spec_path.display()
        ),
    }
    println!(
        "  shipped: {}",
        if plan.shipped.is_empty() {
            format!("none ({} does not exist)", shipped_path.display())
        } else {
            plan.shipped.join(", ")
        }
    );
    for library in &inputs.libraries {
        println!("  native: {} (sha256 {})", library.entry, library.sha256);
    }
    for line in &plan.stats {
        println!("  {line}");
    }

    println!("\nWrote {} files to {}:", plan.files.len(), args.out.display());
    for file in &plan.files {
        println!(
            "  {:<24} {:>9} bytes  {}",
            file.path,
            file.bytes.len(),
            file.note
        );
    }

    if !plan.skipped.is_empty() {
        println!("\nSkipped {} files:", plan.skipped.len());
        for (path, reason) in &plan.skipped {
            println!("  {path:<24} {reason}");
        }
    }

    if args.require_complete && !plan.skipped.is_empty() {
        bail!(
            "{} resource files could not be produced; rerun without --require-complete to accept a partial tree",
            plan.skipped.len()
        );
    }
    Ok(())
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
        let inputs = data::Inputs::read(&mut archive).unwrap();
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
            assert!(tables.contains_key(name), "type {kind} names unknown table {name}");
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
        assert!(kinds.windows(2).all(|pair| pair[0] < pair[1]), "starter kinds are not ascending");
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
