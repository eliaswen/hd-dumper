//! Command-line front end of the [`hd_dumper`] library.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;

use hd_dumper::progress::Console;
use hd_dumper::{Options, Source};

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
    /// leave empty. Default: an installed `client-spec.toml` if there is one,
    /// otherwise the copy built into this program.
    #[arg(long, conflicts_with = "no_spec")]
    spec: Option<PathBuf>,

    /// Use no spec: skip order-resources.json and starter/layout.json.
    #[arg(long)]
    no_spec: bool,

    /// The two command tables that ship with this tool, as a directory.
    /// Default: an installed `shipped` directory if there is one, otherwise
    /// the copies built into this program.
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

fn main() -> Result<()> {
    let args = Args::parse();
    let options = Options {
        apk: args.apk.clone(),
        out: args.out.clone(),
        spec: match (args.spec, args.no_spec) {
            (_, true) => Source::Skip,
            (Some(path), false) => Source::Path(path),
            (None, false) => Source::Default,
        },
        shipped: args.shipped.map_or(Source::Default, Source::Path),
        type_map: args.type_map,
        require_complete: false,
    };
    let summary = hd_dumper::dump(&options, &mut Console::new())?;

    println!("APK: {} (sha256 {})", args.apk.display(), summary.apk_sha256);
    match &summary.spec {
        Ok(spec) => println!("  spec: {spec}"),
        Err(reason) => println!(
            "  spec: none ({reason}; order-resources.json and starter/layout.json will be skipped)"
        ),
    }
    match &summary.shipped {
        Ok(files) => println!("  shipped: {}", files.join(", ")),
        Err(reason) => println!("  shipped: none ({reason})"),
    }
    for (entry, sha256) in &summary.libraries {
        println!("  native: {entry} (sha256 {sha256})");
    }
    for line in &summary.stats {
        println!("  {line}");
    }

    println!("\nWrote {} files to {}:", summary.files.len(), args.out.display());
    for file in &summary.files {
        println!("  {:<24} {:>9} bytes  {}", file.path, file.bytes, file.note);
    }

    if !summary.skipped.is_empty() {
        println!("\nSkipped {} files:", summary.skipped.len());
        for (path, reason) in &summary.skipped {
            println!("  {path:<24} {reason}");
        }
    }

    if args.require_complete && !summary.skipped.is_empty() {
        bail!(
            "{} resource files could not be produced; rerun without --require-complete to accept a partial tree",
            summary.skipped.len()
        );
    }
    Ok(())
}
