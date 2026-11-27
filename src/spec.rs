//! The client facts an APK's data tables do not contain.
//!
//! Everything else this tool writes is a rule over the APK's own CSVs. Three
//! outputs need facts only the client's own code holds — `money.csv`'s data-type
//! number, the order generator's candidate walk, and the UnlockLevel of rows
//! whose CSV cell is empty — so they come from a spec file the caller supplies,
//! never from constants in this program.
//!
//! ```toml
//! # Optional: pin money.csv's data-type number instead of deriving it.
//! money_type = 19
//!
//! # UnlockLevel for a walked row whose CSV cell is empty or absent.
//! unlock_default = 1
//!
//! [[walk]]
//! table = "animal_feed"
//! type = 16
//!
//! # Per-row exceptions to unlock_default. A row override wins over the CSV.
//! [[unlock_row]]
//! table = "animal_feed"
//! name = "Chicken Food"
//! level = 1
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The spec that ships with the tool, compiled in so the tool needs no files
/// beside it (an Android app, a lone `.exe`).
const BUNDLED: &str = include_str!("../client-spec.toml");
/// How the compiled-in spec is named in reports and `sources.json`.
pub const BUNDLED_LABEL: &str = "(built-in) client-spec.toml";

pub struct Spec {
    pub path: PathBuf,
    /// `money.csv`'s data-type number, if the caller pinned it.
    pub money_type: Option<u32>,
    /// Order-candidate tables, in the client's walk order.
    pub walk: Vec<(String, u32)>,
    /// Types the client allocates avatar bitsets for, in the client's order.
    pub layout_types: Vec<u32>,
    /// UnlockLevel used when a walked row's CSV cell is empty or absent.
    pub unlock_default: Option<u32>,
    /// UnlockLevel overrides, keyed by table then row name.
    pub unlock_rows: BTreeMap<String, BTreeMap<String, u32>>,
}

impl Spec {
    /// Read a spec file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading spec {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// The `client-spec.toml` compiled into this tool.
    pub fn bundled() -> Result<Self> {
        Self::parse(BUNDLED, Path::new(BUNDLED_LABEL))
    }

    /// Parse spec `text`; `path` names it in messages and in `sources.json`.
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing spec {}", path.display()))?;

        let money_type = integer(&value, "money_type", path)?.map(|value| {
            u32::try_from(value).context("money_type does not fit an unsigned integer")
        });
        let money_type = money_type.transpose()?;
        let unlock_default = integer(&value, "unlock_default", path)?.map(|value| {
            u32::try_from(value).context("unlock_default does not fit an unsigned integer")
        });
        let unlock_default = unlock_default.transpose()?;

        let mut walk = Vec::new();
        if let Some(entries) = value.get("walk") {
            let entries = entries
                .as_array()
                .with_context(|| format!("walk must be an array of tables in {}", path.display()))?;
            for entry in entries {
                let table = entry
                    .get("table")
                    .and_then(toml::Value::as_str)
                    .with_context(|| {
                        format!("every [[walk]] entry needs a table name in {}", path.display())
                    })?;
                let kind = integer(entry, "type", path)?.with_context(|| {
                    format!("every [[walk]] entry needs an integer type in {}", path.display())
                })?;
                walk.push((
                    table.to_string(),
                    u32::try_from(kind)
                        .context("a walked data-type number does not fit an unsigned integer")?,
                ));
            }
        }

        let mut layout_types = Vec::new();
        if let Some(entries) = value.get("layout_types") {
            let entries = entries.as_array().with_context(|| {
                format!(
                    "layout_types must be an array of integers in {}",
                    path.display()
                )
            })?;
            for entry in entries {
                let kind = entry.as_integer().with_context(|| {
                    format!("layout_types must be integers in {}", path.display())
                })?;
                layout_types.push(
                    u32::try_from(kind)
                        .context("a layout data-type number does not fit an unsigned integer")?,
                );
            }
        }

        let mut unlock_rows: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
        if let Some(entries) = value.get("unlock_row") {
            let entries = entries.as_array().with_context(|| {
                format!("unlock_row must be an array of tables in {}", path.display())
            })?;
            for entry in entries {
                let table = entry
                    .get("table")
                    .and_then(toml::Value::as_str)
                    .with_context(|| {
                        format!(
                            "every [[unlock_row]] entry needs a table name in {}",
                            path.display()
                        )
                    })?;
                let name = entry
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .with_context(|| {
                        format!(
                            "every [[unlock_row]] entry needs a row name in {}",
                            path.display()
                        )
                    })?;
                let level = integer(entry, "level", path)?.with_context(|| {
                    format!(
                        "every [[unlock_row]] entry needs an integer level in {}",
                        path.display()
                    )
                })?;
                unlock_rows
                    .entry(table.to_string())
                    .or_default()
                    .insert(
                        name.to_string(),
                        u32::try_from(level)
                            .context("an unlock level does not fit an unsigned integer")?,
                    );
            }
        }

        if money_type.is_none() && walk.is_empty() && layout_types.is_empty() {
            bail!(
                "spec {} pins nothing: it needs money_type, a [[walk]], a layout_types list, or any combination",
                path.display()
            );
        }
        Ok(Self {
            path: path.to_path_buf(),
            money_type,
            walk,
            layout_types,
            unlock_default,
            unlock_rows,
        })
    }
}

fn integer(value: &toml::Value, key: &str, path: &Path) -> Result<Option<i64>> {
    match value.get(key) {
        None => Ok(None),
        Some(value) => Ok(Some(value.as_integer().with_context(|| {
            format!("{key} must be an integer in {}", path.display())
        })?)),
    }
}
