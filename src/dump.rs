//! The resource files `hd-server` loads, derived from the APK's data tables.
//!
//! Every generator is a rule over the APK's own CSVs. Where a rule needs a name
//! — a column the server's reader depends on — that name is the interface
//! between this tool and the server, and nothing else is assumed.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};

use crate::data::{Csv, Inputs, Record};
use crate::native::{self, TypeMap};
use crate::spec::Spec;

pub struct File {
    /// Path relative to the output directory.
    pub path: String,
    pub bytes: Vec<u8>,
    /// One line of provenance for the report.
    pub note: String,
}

/// Everything one run draws on.
pub struct Sources<'a> {
    pub inputs: &'a Inputs,
    pub spec: Option<&'a Spec>,
    /// The client's data-type registry, from the scan or from `--type-map`.
    pub types: Option<&'a TypeMap>,
    /// The command tables that ship with the tool, with their hashes.
    pub shipped: Option<Vec<(&'a native::Shipped, Vec<u8>, String)>>,
}

pub struct Plan {
    pub files: Vec<File>,
    /// Files copied in from the tool rather than derived from this APK.
    pub shipped: Vec<&'static str>,
    /// Outputs this run could not produce, with the reason.
    pub skipped: Vec<(String, String)>,
    pub stats: Vec<String>,
}

impl Plan {
    pub fn build(sources: &Sources) -> Result<Self> {
        let inputs = sources.inputs;
        let mut skipped = Vec::new();
        let mut stats = Vec::new();
        let mut files = vec![
            exp_levels(inputs)?,
            document(inputs, "level_0")?,
            document(inputs, "game_config")?,
        ];
        match greg_home(inputs) {
            Ok(file) => files.push(file),
            Err(reason) => skipped.push(("home-greg.json".to_string(), format!("{reason:#}"))),
        }
        let (tables, table_stats) = replay_tables(inputs)?;
        files.push(tables);
        stats.extend(table_stats);
        files.push(replay_config(inputs)?);
        match money_ids(inputs, sources.spec) {
            Ok(file) => files.push(file),
            Err(reason) => skipped.push((
                "money-ids.json".to_string(),
                format!("{reason:#}; pin money_type in the spec to settle it"),
            )),
        }
        match order_resources(inputs, sources.spec) {
            Ok(file) => files.push(file),
            Err(reason) => skipped.push((
                "order-resources.json".to_string(),
                format!("{reason:#}; the spec has to carry its walk"),
            )),
        }
        match sources.types {
            Some(types) => {
                stats.push(format!("type registry: {}", types.evidence));
                files.push(replay_type_tables(types, inputs)?);
                files.push(starter_tables(types, inputs)?);
                match sources.spec {
                    Some(spec) => files.push(starter_layout(types, inputs, spec)?),
                    None => skipped.push((
                        "starter/layout.json".to_string(),
                        "no spec was supplied; layout_types has to list the types the client \
                         allocates avatar bitsets for"
                            .to_string(),
                    )),
                }
            }
            None => {
                for path in [
                    "replay-type-tables.json",
                    "starter/tables.json",
                    "starter/layout.json",
                ] {
                    skipped.push((
                        path.to_string(),
                        "no data types: this APK has no x86 or arm64-v8a libg.so to scan; pass --type-map"
                            .to_string(),
                    ));
                }
            }
        }

        let mut shipped = Vec::new();
        if let Some(entries) = &sources.shipped {
            for (entry, bytes, hash) in entries {
                shipped.push(entry.path);
                files.push(File {
                    path: entry.path.to_string(),
                    bytes: bytes.clone(),
                    note: format!("shipped {hash:.12} — {}", entry.origin),
                });
            }
        } else {
            for entry in native::SHIPPED {
                skipped.push((
                    entry.path.to_string(),
                    "not shipped: pass --shipped to the directory holding it".to_string(),
                ));
            }
        }

        files.push(sources_manifest(sources, &files)?);
        Ok(Self {
            files,
            shipped,
            skipped,
            stats,
        })
    }
}

/// `exp-levels.csv`: the level ladder the server's progression reader parses
/// positionally, one row per level, in level order.
fn exp_levels(inputs: &Inputs) -> Result<File> {
    let csv = inputs
        .csv("exp_levels")
        .context("APK has no assets/data/exp_levels.csv")?;
    let level_column = csv
        .column("Level")
        .context("exp_levels.csv has no Level column")?;
    let xp_column = csv
        .column("ExpToNextLevel")
        .context("exp_levels.csv has no ExpToNextLevel column")?;

    let mut out = String::from("Level,ExpToNextLevel\n");
    let mut expected = 1u32;
    for record in csv.records.iter().skip(2) {
        let cell = |index: usize| record.get(index).map(String::as_str).unwrap_or("").trim();
        let level = cell(level_column);
        if level.is_empty() {
            continue;
        }
        let level: u32 = level
            .parse()
            .with_context(|| format!("exp_levels.csv level '{level}' is not a number"))?;
        ensure!(
            level == expected,
            "exp_levels.csv is not a contiguous level ladder: expected level {expected}, found {level}"
        );
        let requirement = cell(xp_column);
        requirement.parse::<u32>().with_context(|| {
            format!("exp_levels.csv level {level} requirement '{requirement}' is not a number")
        })?;
        out.push_str(&format!("{level},{requirement}\n"));
        expected += 1;
    }
    ensure!(
        expected > 100,
        "exp_levels.csv carries only {} levels; refusing to guess at this build",
        expected - 1
    );
    Ok(File {
        path: "exp-levels.csv".into(),
        bytes: out.into_bytes(),
        note: format!("{} levels", expected - 1),
    })
}

/// `home-greg.json`: Greg's AI farm. The server reads it as three blobs `a`, `b`
/// and `c` (the same wrapper its own `--extract-ai-home` builds): `c` is the
/// client's `ai.json` unchanged, `a` and `b` are empty objects.
fn greg_home(inputs: &Inputs) -> Result<File> {
    const SOURCE: &str = "ai.json";
    let farm = inputs
        .documents
        .get(SOURCE)
        .with_context(|| format!("APK has no assets/data/{SOURCE}"))?;
    ensure!(farm.is_object(), "assets/data/{SOURCE} is not a JSON object");
    Ok(File {
        path: "home-greg.json".into(),
        bytes: json_lines(&json!({"a": {}, "b": {}, "c": farm}))?,
        note: format!("Greg's farm: assets/data/{SOURCE} as blob c"),
    })
}

/// A CSV reproduced verbatim as a JSON array of records: `starter/level_0.json`
/// and `starter/game_config.json` are the server's own inputs, and it walks
/// their section markers itself.
fn document(inputs: &Inputs, stem: &str) -> Result<File> {
    let csv = inputs
        .csv(stem)
        .with_context(|| format!("APK has no assets/data/{stem}.csv"))?;
    let marker = match stem {
        "level_0" => "Objects",
        "game_config" => "InitialAvatar",
        _ => "",
    };
    ensure!(
        csv.records
            .iter()
            .any(|record| record.first().map(String::as_str).unwrap_or("") == marker),
        "{stem}.csv carries no '{marker}' section; refusing to guess at this build"
    );
    Ok(File {
        path: format!("starter/{stem}.json"),
        bytes: json_lines(&records_value(&csv.records))?,
        note: format!("{} records", csv.records.len()),
    })
}

/// `replay-tables.json`: every data table the structural rule accepted, each
/// record carrying the full column set so a reader can index any column it
/// knows by name.
fn replay_tables(inputs: &Inputs) -> Result<(File, Vec<String>)> {
    let mut tables = Map::new();
    let mut rows = 0usize;
    let mut ragged = 0usize;
    for stem in &inputs.tables {
        let csv = inputs.csv(stem).expect("classified table is present");
        let columns = columns(csv);
        let mut table = Vec::new();
        for record in csv.data_rows() {
            if record.len() > csv.header().len() {
                ragged += 1;
            }
            let mut row = Map::new();
            for (index, name) in &columns {
                row.insert(
                    name.clone(),
                    Value::String(record.get(*index).cloned().unwrap_or_default()),
                );
            }
            table.push(Value::Object(row));
            rows += 1;
        }
        tables.insert(stem.clone(), Value::Array(table));
    }
    ensure!(!tables.is_empty(), "no data tables were recognised");

    let mut stats = vec![format!(
        "{} tables, {rows} records{}",
        tables.len(),
        if ragged > 0 {
            format!(", {ragged} rows wider than their header")
        } else {
            String::new()
        }
    )];
    for (stem, reason) in &inputs.excluded {
        stats.push(format!("not a data table: {stem} ({reason})"));
    }
    Ok((
        File {
            path: "replay-tables.json".into(),
            bytes: json_lines(&Value::Object(tables))?,
            note: format!("{} tables, {rows} records", inputs.tables.len()),
        },
        stats,
    ))
}

/// `replay-config.json`: every `game_config.csv` row that carries an unsigned
/// integer, keyed by the row name. The server reads the handful of keys it
/// knows and ignores the rest.
fn replay_config(inputs: &Inputs) -> Result<File> {
    let csv = inputs
        .csv("game_config")
        .context("APK has no assets/data/game_config.csv")?;
    let value_column = csv
        .column("IntValue")
        .context("game_config.csv has no IntValue column")?;

    let mut config = Map::new();
    let mut skipped = 0usize;
    for record in csv.records.iter().skip(2) {
        let name = record.first().map(String::as_str).unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let raw = record
            .get(value_column)
            .map(String::as_str)
            .unwrap_or("")
            .trim();
        match raw.parse::<u32>() {
            Ok(value) => {
                config.insert(name.to_string(), json!(value));
            }
            Err(_) if !raw.is_empty() => skipped += 1,
            Err(_) => {}
        }
    }
    ensure!(
        !config.is_empty(),
        "game_config.csv carries no integer rows; refusing to guess at this build"
    );
    Ok(File {
        path: "replay-config.json".into(),
        bytes: json_lines(&Value::Object(config.clone()))?,
        note: format!(
            "{} keys{}",
            config.len(),
            if skipped > 0 {
                format!(", {skipped} non-integer rows ignored")
            } else {
                String::new()
            }
        ),
    })
}

/// `money-ids.json`: the data ID of every `money.csv` row, which is the money
/// table's data-type number times 100000 plus the row's position among the
/// table's named rows.
///
/// The values and their order come from the CSV. The type number is derived
/// from the APK itself: the client's own documents reference IDs that name a
/// `money.csv` row, and the prefix those IDs share is the type number — unless
/// the spec pins it.
fn money_ids(inputs: &Inputs, spec: Option<&Spec>) -> Result<File> {
    let csv = inputs
        .csv("money")
        .context("APK has no assets/data/money.csv")?;
    let named: Vec<&Record> = csv.named_rows().collect();
    ensure!(!named.is_empty(), "money.csv has no named rows");

    let (kind, evidence) = match spec.and_then(|spec| spec.money_type) {
        Some(kind) => (kind, "pinned by the spec".to_string()),
        None => derive_money_type(inputs, &named)?,
    };

    let mut ids = Map::new();
    for (row, record) in named.iter().enumerate() {
        let name = record.first().map(String::as_str).unwrap_or("").trim();
        ids.insert(
            name.to_string(),
            json!(u64::from(kind) * 100_000 + row as u64),
        );
    }
    Ok(File {
        path: "money-ids.json".into(),
        bytes: json_lines(&Value::Object(ids.clone()))?,
        note: format!("{} rows, data type {kind} ({evidence})", ids.len()),
    })
}

/// Derive `money.csv`'s data-type number from the IDs the APK's own files
/// reference: an ID `type * 100000 + row` whose record or field name starts the
/// name of that row of `money.csv` (the client's documents name what they point
/// at, as `BoatOrderComplete` names the stat `BoatOrderCompleteCount`). Exactly
/// one prefix has to win outright, or the derived answer is refused.
fn derive_money_type(inputs: &Inputs, named: &[&Record]) -> Result<(u32, String)> {
    let mut scores: BTreeMap<u32, usize> = BTreeMap::new();
    let mut evidence: BTreeMap<u32, String> = BTreeMap::new();
    for (value, hints) in references(inputs) {
        let row = usize::try_from(value % 100_000).unwrap_or(usize::MAX);
        if row >= named.len() {
            continue;
        }
        let name = normalize(named[row].first().map(String::as_str).unwrap_or(""));
        if name.len() < 5 {
            continue;
        }
        let matched = hints.iter().any(|hint| {
            let hint = normalize(hint);
            hint.len() >= 5 && name.starts_with(&hint)
        });
        if !matched {
            continue;
        }
        let kind = (value / 100_000) as u32;
        *scores.entry(kind).or_default() += 1;
        evidence.entry(kind).or_insert_with(|| {
            format!(
                "{value} names money.csv row {row} '{}'",
                named[row].first().map(String::as_str).unwrap_or("")
            )
        });
    }

    let mut ranked: Vec<(u32, usize)> = scores.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    let Some((kind, score)) = ranked.first().copied() else {
        bail!(
            "no data ID referenced by this APK names a money.csv row, so its data-type number cannot be derived"
        );
    };
    if let Some((runner_up, runner_up_score)) = ranked.get(1).copied() {
        ensure!(
            score > runner_up_score,
            "data type {kind} and {runner_up} both explain {runner_up_score} or more referenced IDs; refusing to guess"
        );
    }
    Ok((
        kind,
        evidence
            .get(&kind)
            .cloned()
            .unwrap_or_else(|| format!("{score} referenced IDs")),
    ))
}

/// `order-resources.json`: the client's order-candidate table, in its walk
/// order. Rows and values come from the CSVs; the walk and the unlock levels
/// the CSVs leave empty come from the spec.
fn order_resources(inputs: &Inputs, spec: Option<&Spec>) -> Result<File> {
    let spec = spec.context("no spec was supplied")?;
    ensure!(
        !spec.walk.is_empty(),
        "spec {} has no [[walk]] entries",
        spec.path.display()
    );

    let mut entries = Vec::new();
    let mut without_order_columns = Vec::new();
    let mut types = Vec::new();
    for (table, kind) in &spec.walk {
        let csv = inputs
            .csv(table)
            .with_context(|| format!("walked table '{table}' is not in assets/data"))?;
        if ["OrderValue", "OrderPrice", "OrderExp", "UnlockLevel"]
            .iter()
            .any(|column| csv.column(column).is_none())
        {
            without_order_columns.push(table.clone());
        }
        types.push(*kind);
        for (row, record) in csv.named_rows().enumerate() {
            let cell = |column: &str| -> &str {
                csv.column(column)
                    .and_then(|index| record.get(index))
                    .map(String::as_str)
                    .unwrap_or("")
                    .trim()
            };
            let name = record.first().map(String::as_str).unwrap_or("").trim();
            let cell_value = cell("UnlockLevel").parse::<u32>().ok();
            let unlock = spec
                .unlock_rows
                .get(table)
                .and_then(|rows| rows.get(name))
                .copied()
                .or(cell_value)
                .or(spec.unlock_default)
                .unwrap_or(0);
            let mut entry = Map::new();
            entry.insert("i".to_string(), json!(entries.len()));
            entry.insert("id".to_string(), json!(u64::from(*kind) * 100_000 + row as u64));
            entry.insert("type".to_string(), json!(kind));
            entry.insert("ov".to_string(), json!(number(cell("OrderValue"))));
            entry.insert("op".to_string(), json!(number(cell("OrderPrice"))));
            entry.insert("oe".to_string(), json!(number(cell("OrderExp"))));
            entry.insert("ul".to_string(), json!(unlock));
            entries.push(Value::Object(entry));
        }
    }

    // The client walks a short curated prefix and then the rest in ascending
    // data-type order, so anything descending later means the spec is wrong.
    let descents: Vec<usize> = types
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0] > pair[1])
        .map(|(index, _)| index + 1)
        .collect();
    let prefix = descents.last().copied().unwrap_or(0);
    let tail_ascends = types[prefix..].windows(2).all(|pair| pair[0] <= pair[1]);
    ensure!(
        tail_ascends,
        "the walk descends after index {prefix} (types {types:?}); check the spec's order and data-type numbers"
    );
    let note = format!(
        "{} entries over {} tables, {} without order columns, curated prefix of {prefix}",
        entries.len(),
        spec.walk.len(),
        without_order_columns.len()
    );
    Ok(File {
        path: "order-resources.json".into(),
        bytes: json_lines(&Value::Array(entries))?,
        note,
    })
}

/// Every data ID the APK's own files reference, with the text that shares its
/// record or field, which is what names the row it points at.
fn references(inputs: &Inputs) -> Vec<(i64, Vec<String>)> {
    let mut out = Vec::new();
    for csv in inputs.csvs.values() {
        for record in &csv.records {
            let hints: Vec<String> = record
                .iter()
                .filter(|cell| {
                    let cell = cell.trim();
                    !cell.is_empty() && cell.parse::<i64>().is_err()
                })
                .cloned()
                .collect();
            for cell in record {
                let cell = cell.trim();
                if let Ok(value) = cell.parse::<i64>() {
                    if (100_000..100_000_000).contains(&value) {
                        out.push((value, hints.clone()));
                    }
                }
            }
        }
    }
    for document in inputs.documents.values() {
        collect_ids(document, "", &mut out);
    }
    out
}

fn collect_ids(value: &Value, key: &str, out: &mut Vec<(i64, Vec<String>)>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                collect_ids(value, key, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_ids(item, key, out);
            }
        }
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if (100_000..100_000_000).contains(&value) {
                    out.push((value, vec![key.to_string()]));
                }
            }
        }
        _ => {}
    }
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn number(cell: &str) -> i64 {
    cell.parse().unwrap_or(0)
}
/// `replay-type-tables.json`: the data-type number of every table the APK ships
/// a CSV for. The server looks tables up by number and ignores the entries it
/// never asks for, so this is the complete registry rather than the subset one
/// release of the server happens to read.
fn replay_type_tables(types: &TypeMap, inputs: &Inputs) -> Result<File> {
    let mut map = Map::new();
    let mut without_csv = 0usize;
    for (kind, stem) in &types.tables {
        if inputs.csv(stem).is_none() {
            without_csv += 1;
            continue;
        }
        map.insert(kind.to_string(), Value::String(stem.clone()));
    }
    ensure!(!map.is_empty(), "no registered table has a CSV in this APK");
    Ok(File {
        path: "replay-type-tables.json".into(),
        bytes: json_lines(&Value::Object(map.clone()))?,
        note: format!(
            "{} types{}",
            map.len(),
            if without_csv > 0 {
                format!(", {without_csv} registered without a CSV in this build")
            } else {
                String::new()
            }
        ),
    })
}

/// `starter/tables.json`: the starter farm's lookup tables, keyed by data-type
/// number. Rows are the table's named rows in file order, carrying the columns
/// the server reads — always present, even where a cell is empty.
fn starter_tables(types: &TypeMap, inputs: &Inputs) -> Result<File> {
    const COLUMNS: [&str; 3] = ["Name", "UnlockLevel", "BrokenPartCount"];
    let mut tables = Vec::new();
    for (kind, stem) in &types.tables {
        let Some(csv) = inputs.csv(stem) else { continue };
        if csv.column("Name").is_none() {
            continue;
        }
        let columns: Vec<(usize, &str)> = COLUMNS
            .iter()
            .filter_map(|name| csv.column(name).map(|index| (index, *name)))
            .collect();
        let mut rows = Vec::new();
        for record in csv.named_rows() {
            let mut row = Map::new();
            for (index, name) in &columns {
                row.insert(
                    (*name).to_string(),
                    Value::String(record.get(*index).cloned().unwrap_or_default()),
                );
            }
            rows.push(Value::Object(row));
        }
        let mut entry = Map::new();
        entry.insert("kind".to_string(), json!(kind));
        entry.insert("rows".to_string(), Value::Array(rows));
        tables.push(Value::Object(entry));
    }
    ensure!(
        !tables.is_empty(),
        "no registered table carries a Name column"
    );
    Ok(File {
        path: "starter/tables.json".into(),
        bytes: json_lines(&Value::Array(tables.clone()))?,
        note: format!("{} tables", tables.len()),
    })
}

/// `starter/layout.json`: the avatar's bitset layout. Which types the client
/// allocates bitsets for, and in which order, comes from the spec; the row and
/// word counts come from the CSVs.
fn starter_layout(types: &TypeMap, inputs: &Inputs, spec: &Spec) -> Result<File> {
    ensure!(
        !spec.layout_types.is_empty(),
        "spec {} has no layout_types",
        spec.path.display()
    );
    ensure!(
        spec.layout_types.windows(2).all(|pair| pair[0] <= pair[1]),
        "spec {} lists layout_types out of order; the client's bitset offsets are cumulative",
        spec.path.display()
    );
    let mut layout = Vec::new();
    let mut words = 0usize;
    for kind in &spec.layout_types {
        let stem = types.tables.get(kind).with_context(|| {
            format!("layout type {kind} is not registered by this build's table binder")
        })?;
        let csv = inputs
            .csv(stem)
            .with_context(|| format!("layout type {kind} ({stem}) has no CSV in this APK"))?;
        let named = csv.named_rows().count();
        let records = csv
            .records
            .iter()
            .skip(2)
            .filter(|record| record.iter().any(|cell| !cell.trim().is_empty()))
            .count();
        words += named.div_ceil(32);
        layout.push(json!([
            kind,
            format!("data/{stem}.csv"),
            named,
            records,
            named.div_ceil(32)
        ]));
    }
    Ok(File {
        path: "starter/layout.json".into(),
        bytes: json_lines(&Value::Array(layout.clone()))?,
        note: format!("{} types, {} bytes of bitsets", layout.len(), words * 4),
    })
}

/// `sources.json`: what this tree was derived from. The server ignores it; it
/// exists so a generated tree can be traced to one APK and one run.
fn sources_manifest(sources: &Sources, written: &[File]) -> Result<File> {
    let inputs = sources.inputs;
    let mut inputs_map = Map::new();
    for (entry, hash) in &inputs.hashes {
        inputs_map.insert(entry.clone(), json!(hash));
    }
    let mut generated = Map::new();
    for file in written {
        generated.insert(
            file.path.clone(),
            json!(crate::apk::sha256_hex(&file.bytes)),
        );
    }
    let mut document = Map::new();
    document.insert(
        "tool".to_string(),
        json!(format!("hd-dumper {}", env!("CARGO_PKG_VERSION"))),
    );
    document.insert("apk_sha256".to_string(), json!(inputs.apk_sha256));
    document.insert("inputs".to_string(), Value::Object(inputs_map));
    document.insert(
        "data_tables".to_string(),
        json!({
            "count": inputs.tables.len(),
            "excluded": inputs
                .excluded
                .iter()
                .map(|(stem, reason)| json!({"file": stem, "reason": reason}))
                .collect::<Vec<_>>(),
        }),
    );
    document.insert(
        "native_libraries".to_string(),
        Value::Array(
            inputs
                .libraries
                .iter()
                .map(|library| {
                    json!({"abi": library.abi, "entry": library.entry, "sha256": library.sha256})
                })
                .collect(),
        ),
    );
    document.insert("generated".to_string(), Value::Object(generated));
    document.insert(
        "shipped".to_string(),
        Value::Array(
            native::SHIPPED
                .iter()
                .map(|entry| json!({"file": entry.path, "carries": entry.carries, "origin": entry.origin}))
                .collect(),
        ),
    );
    document.insert(
        "type_registry".to_string(),
        match sources.types {
            Some(types) => json!({
                "evidence": types.evidence,
                "count": types.tables.len(),
            }),
            None => Value::Null,
        },
    );
    document.insert(
        "spec".to_string(),
        match sources.spec {
            Some(spec) => json!({
                "path": spec.path.to_string_lossy(),
                "walk": spec
                    .walk
                    .iter()
                    .map(|(table, kind)| json!({"table": table, "type": kind}))
                    .collect::<Vec<_>>(),
                "layout_types": spec.layout_types,
                "money_type": spec.money_type,
            }),
            None => Value::Null,
        },
    );
    Ok(File {
        path: "sources.json".into(),
        bytes: json_lines(&Value::Object(document))?,
        note: format!("{} inputs hashed", inputs.hashes.len()),
    })
}

/// Column names of a table in header order, blank and duplicate names dropped.
fn columns(csv: &Csv) -> Vec<(usize, String)> {
    let mut columns: Vec<(usize, String)> = Vec::new();
    for (index, cell) in csv.header().iter().enumerate() {
        let name = cell.trim();
        if name.is_empty() || columns.iter().any(|(_, seen)| seen == name) {
            continue;
        }
        columns.push((index, name.to_string()));
    }
    columns
}

fn records_value(records: &[Record]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|record| {
                Value::Array(record.iter().map(|cell| Value::String(cell.clone())).collect())
            })
            .collect(),
    )
}

fn json_lines(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
