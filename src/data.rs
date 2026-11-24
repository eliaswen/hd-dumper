//! The APK's `assets/data` CSVs, and the structural rule that decides which of
//! them are data tables.
//!
//! Rules only: no table names, type numbers, column names or values are baked
//! into this tool. A data table is recognised by shape — its first record names
//! columns and its second record carries the column types, whose vocabulary is
//! derived from the APK itself (a token has to appear in the second record of at
//! least two files). Sectioned documents such as `level_0.csv` fail that test
//! and are handled as documents instead.

use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;

use anyhow::{Context, Result, ensure};

use crate::apk::{Archive, sha256_hex};
use crate::native::{self, Library};

/// One CSV record: the cells of one physical line, with quotes resolved.
pub type Record = Vec<String>;

pub const DATA_PREFIX: &str = "assets/data/";
pub const FINGERPRINT: &str = "assets/fingerprint.json";
pub const SETTINGS: &str = "assets/settings_template.csv";

pub struct Csv {
    /// File name without `.csv`: the name the server uses to look a table up.
    pub stem: String,
    pub records: Vec<Record>,
}

impl Csv {
    pub fn header(&self) -> &Record {
        &self.records[0]
    }

    /// Records that define an entry of their table: the named ones.
    pub fn named_rows(&self) -> impl Iterator<Item = &Record> {
        self.records
            .iter()
            .skip(2)
            .filter(|record| {
                record
                    .first()
                    .is_some_and(|cell| !cell.trim().is_empty())
            })
    }

    /// Records after the two preamble rows, dropping entirely blank ones.
    pub fn data_rows(&self) -> impl Iterator<Item = &Record> {
        self.records
            .iter()
            .skip(2)
            .filter(|record| record.iter().any(|cell| !cell.trim().is_empty()))
    }

    pub fn column(&self, name: &str) -> Option<usize> {
        self.header()
            .iter()
            .position(|cell| cell.trim().eq_ignore_ascii_case(name))
    }
}

pub struct Inputs {
    pub apk_sha256: String,
    /// Every parsed `assets/data/*.csv`, keyed by stem.
    pub csvs: BTreeMap<String, Csv>,
    /// Every parsed `assets/data/*.json`, keyed by file name. These are the
    /// client's own documents (AI farms and town), and they name data IDs.
    pub documents: BTreeMap<String, serde_json::Value>,

    /// Stems the structural rule accepted, sorted.
    pub tables: Vec<String>,
    /// Stems the structural rule rejected, with the reason.
    pub excluded: Vec<(String, String)>,
    /// SHA-256 of every APK entry the output was derived from.
    pub hashes: BTreeMap<String, String>,
    pub libraries: Vec<Library>,
}

impl Inputs {
    pub fn csv(&self, stem: &str) -> Option<&Csv> {
        self.csvs.get(stem)
    }

    pub fn read(apk: &mut Archive) -> Result<Self> {
        let entries = apk.under(DATA_PREFIX);
        ensure!(
            !entries.is_empty(),
            "APK has no {} entries; is this a Hay Day APK?",
            DATA_PREFIX
        );

        let mut csvs = BTreeMap::new();
        let mut documents = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        let total = entries.len();
        let live = std::io::stderr().is_terminal();
        for (index, entry) in entries.iter().enumerate() {
            if live && (index % 16 == 0 || index + 1 == total) {
                eprint!("\r\x1b[2KReading assets/data [{}/{}] {entry}", index + 1, total);
            }
            let bytes = apk.read(entry)?;
            if let Some(stem) = entry
                .strip_prefix(DATA_PREFIX)
                .and_then(|name| name.strip_suffix(".csv"))
            {
                let records =
                    parse_records(&bytes).with_context(|| format!("parsing {entry}"))?;
                csvs.insert(
                    stem.to_string(),
                    Csv {
                        stem: stem.to_string(),
                        records,
                    },
                );
            } else if entry.ends_with(".json") {
                let document: serde_json::Value = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {entry} as JSON"))?;
                let name = entry
                    .rsplit_once('/')
                    .map(|(_, name)| name)
                    .unwrap_or(entry)
                    .to_string();
                documents.insert(name, document);
            } else {
                continue;
            }
            hashes.insert(entry.clone(), sha256_hex(&bytes));
        }
        if live {
            eprintln!();
        } else {
            eprintln!("Read {total} assets/data entries");
        }
        ensure!(
            csvs.len() >= 100,
            "only {} data CSVs in this APK; refusing to guess at this build",
            csvs.len()
        );
        ensure!(
            !documents.is_empty(),
            "APK has no assets/data/*.json documents"
        );

        let vocabulary = type_vocabulary(&csvs);
        let mut tables = Vec::new();
        let mut excluded = Vec::new();
        for (stem, csv) in &csvs {
            match classify(csv, &vocabulary) {
                Ok(()) => tables.push(stem.clone()),
                Err(reason) => excluded.push((csv.stem.clone(), reason)),
            }
        }

        for entry in [FINGERPRINT, SETTINGS] {
            ensure!(
                apk.names().iter().any(|name| name == entry),
                "APK has no {entry}; is this a Hay Day APK?"
            );
            hashes.insert(entry.to_string(), sha256_hex(&apk.read(entry)?));
        }

        let libraries = native::libraries(apk)?;
        ensure!(
            !libraries.is_empty(),
            "APK carries no lib/*/libg.so; is this a Hay Day APK?"
        );

        Ok(Self {
            apk_sha256: apk.sha256().to_string(),
            csvs,
            documents,
            tables,
            excluded,
            hashes,
            libraries,
        })
    }
}

/// Tokens used as a column type in at least two files, derived from the APK.
fn type_vocabulary(csvs: &BTreeMap<String, Csv>) -> BTreeSet<String> {
    let mut files: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for csv in csvs.values() {
        if csv.records.len() < 2 {
            continue;
        }
        for cell in &csv.records[1] {
            let token = cell.trim();
            if !token.is_empty() {
                files
                    .entry(token.to_string())
                    .or_default()
                    .insert(csv.stem.as_str());
            }
        }
    }
    files
        .into_iter()
        .filter(|(_, stems)| stems.len() >= 2)
        .map(|(token, _)| token)
        .collect()
}

fn classify(csv: &Csv, vocabulary: &BTreeSet<String>) -> Result<(), String> {
    if csv.records.len() < 2 {
        return Err(format!("only {} record(s)", csv.records.len()));
    }
    let types: BTreeSet<&str> = csv.records[1]
        .iter()
        .map(|cell| cell.trim())
        .filter(|token| !token.is_empty())
        .collect();
    if types.is_empty() {
        return Err("no column-type record".to_string());
    }
    let unknown: Vec<&&str> = types
        .iter()
        .filter(|token| !vocabulary.contains(**token))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "column types {} appear in no other table",
            unknown
                .iter()
                .map(|token| format!("'{token}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(())
}

/// Parse a CSV file the way the game's tables are laid out: one record per
/// logical record, quotes resolved, duplicate quotes unescaped and blank cells
/// preserved. A quotation left open at the end of a line continues the record on
/// the next physical line — the client's own documents contain stray quotes, and
/// a reader that ends the record at the newline splits them differently.
pub fn parse_records(bytes: &[u8]) -> Result<Vec<Record>> {
    let text = std::str::from_utf8(bytes).context("not valid UTF-8")?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records = Vec::new();
    let mut record: Record = Vec::new();
    let mut quoted = false;
    for line in text.lines() {
        let mut chars = line.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '"' if quoted => {
                    if chars.peek() == Some(&'"') {
                        record.last_mut().expect("quoted field").push('"');
                        chars.next();
                    } else {
                        quoted = false;
                    }
                }
                // A quotation only opens a field, never a field's middle.
                '"' if record.is_empty() || record.last().is_some_and(String::is_empty) => {
                    if record.is_empty() {
                        record.push(String::new());
                    }
                    quoted = true;
                }
                ',' if !quoted => {
                    // A separator always materializes the field before it.
                    if record.is_empty() {
                        record.push(String::new());
                    }
                    record.push(String::new());
                }
                _ => {
                    if record.is_empty() {
                        record.push(String::new());
                    }
                    record.last_mut().expect("current field").push(character);
                }
            }
        }
        if !quoted {
            records.push(std::mem::take(&mut record));
        }
    }
    if !record.is_empty() {
        records.push(record);
    }
    Ok(records)
}

pub fn parse_line(line: &str) -> Record {
    parse_records(line.as_bytes())
        .ok()
        .and_then(|records| records.into_iter().next())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_commas_and_blanks_round_trip() {
        assert_eq!(
            parse_line("\"a,b\",c,,\"d\"\"e\""),
            vec!["a,b", "c", "", "d\"e"]
        );
        // Python's reader yields no fields at all for a blank line.
        assert_eq!(parse_line(""), Vec::<String>::new());
        assert_eq!(parse_line("a,b,"), vec!["a", "b", ""]);
        assert_eq!(parse_line("\"\""), vec![""]);
    }

    #[test]
    fn a_quote_inside_an_unquoted_field_is_literal() {
        assert_eq!(parse_line("ab\"c,d"), vec!["ab\"c", "d"]);
    }

    #[test]
    fn an_unterminated_quote_continues_the_record() {
        let records = parse_records("a,\"b\nc\",d\n".as_bytes()).unwrap();
        assert_eq!(records, vec![vec!["a", "bc", "d"]]);
    }

    #[test]
    fn bom_and_line_endings_are_handled() {
        let records = parse_records("\u{feff}A,B\r\n1,2\r\n3,4\r\n".as_bytes()).unwrap();
        assert_eq!(records, vec![vec!["A", "B"], vec!["1", "2"], vec!["3", "4"]]);
    }

    #[test]
    fn documents_fail_the_table_rule() {
        let document = Csv {
            stem: "level_0".into(),
            records: vec![
                vec!["TileMap".into(), String::new()],
                vec![String::new(), "t".into(), "e".into()],
            ],
        };
        let table = Csv {
            stem: "fields".into(),
            records: vec![
                vec!["Name".into(), "Value".into()],
                vec!["String".into(), "int".into()],
            ],
        };
        let mut csvs = BTreeMap::new();
        csvs.insert("level_0".to_string(), document);
        csvs.insert("fields".to_string(), table);
        csvs.insert(
            "animals".to_string(),
            Csv {
                stem: "animals".into(),
                records: vec![
                    vec!["Name".into(), "Value".into()],
                    vec!["String".into(), "int".into()],
                ],
            },
        );
        let vocabulary = type_vocabulary(&csvs);
        assert_eq!(vocabulary, BTreeSet::from(["String".to_string(), "int".to_string()]));
        assert!(classify(&csvs["fields"], &vocabulary).is_ok());
        assert!(classify(&csvs["level_0"], &vocabulary).is_err());
    }
}
