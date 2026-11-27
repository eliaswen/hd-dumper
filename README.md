# hd-dumper

Extracts the runtime resource tables that
[hd-server](https://github.com/eliaswen/hd-server) loads from an APK you supply,
so the server can run without shipping any game data of its own.

It is a research and preservation tool for people running their own compatible
server. It is **not affiliated with, endorsed by or sponsored by Supercell**. No
game assets are redistributed: the data tables are read out of the APK you point
it at, and the two protocol tables that cannot be (see
[What ships with the tool](#what-ships-with-the-tool)) are interface facts, not
content. See the [legal notice](LEGAL.md).

## Install

Each [release](https://github.com/eliaswen/hd-dumper/releases) has archives for
Linux, macOS and Windows. On Linux you can install from the signed apt or dnf
repository instead; [eliaswen.github.io/hd-dumper](https://eliaswen.github.io/hd-dumper/)
has the setup commands.

## Build

```sh
cargo build --release
```

## Usage

```sh
hd-dumper --apk hayday.apk --out resources
```

| Option | Meaning |
| --- | --- |
| `--apk` | Input Hay Day APK (1.43.150 build 1598, x86 or arm64-v8a). |
| `-o, --out` | Output directory, the server's `resources_dir` (default `resources`). |
| `--spec` | Client facts the APK's data tables do not contain (default: the bundled `client-spec.toml`; see below). |
| `--shipped` | Directory holding the two protocol tables that ship with the tool (default: the bundled `shipped/`). |
| `--type-map` | Data-type registry as JSON, for an APK with no x86 or arm64-v8a `libg.so` to scan. |
| `--require-complete` | Exit non-zero when anything could not be produced. |

The bundled files are looked up in the working directory, then next to the
executable (release archives), then in `../share/hd-dumper` beside it (system
packages, which install them to `/usr/share/hd-dumper`).

Then run the server against it:

```sh
hd-server --resources-dir resources --config config.toml
```

## What it writes

Fourteen files: every one the server reads, plus `sources.json`.

| File | Derived from |
| --- | --- |
| `exp-levels.csv` | `exp_levels.csv`, reduced to the level ladder the progression reader parses (`Level`, `ExpToNextLevel`), one row per level in level order. |
| `starter/level_0.json` | `level_0.csv`, verbatim as an array of records. The server walks its section markers itself. |
| `starter/game_config.json` | `game_config.csv`, verbatim as an array of records. |
| `starter/tables.json` | the starter farm's tables, keyed by data-type number: every registered table that has a `Name` column, with the rows and columns the starter reads. |
| `starter/layout.json` | the avatar's bitset layout: the types the spec lists (which the client allocates bitsets for) with the row and word counts the CSVs give. |
| `replay-tables.json` | every data table in `assets/data`, each record carrying the table's full column set, so the replay can index any column by name. |
| `replay-type-tables.json` | the client's data-type registry, as scanned out of `libg.so` (see below). |
| `replay-config.json` | every `game_config.csv` row with an unsigned integer value, keyed by row name. The server reads the keys it knows and ignores the rest. |
| `money-ids.json` | every named row of `money.csv`, as `name -> data-type * 100000 + row`. The data type is derived from the APK: IDs in the client's own shipped documents (`assets/data/ai.json`, `ai_town.json`, `open_graph_objects.csv`) that name a `money.csv` row share its prefix, and one prefix has to win outright. |
| `order-resources.json` | the order generator's table: rows and their `OrderValue`/`OrderPrice`/`OrderExp`/`UnlockLevel` come from the CSVs, in the walk order and with the empty unlock levels the spec supplies. |
| `home-greg.json` | Greg's AI farm: `assets/data/ai.json` unchanged as blob `c`, with empty `a` and `b`, the layout the server's `home-greg.json` reader expects. |
| `command-schema.json`, `command-evidence.json` | ships with the tool; see below. |
| `sources.json` | provenance: the APK's SHA-256, the SHA-256 of every input entry, the spec and registry it used, and the SHA-256 of every file written. The server ignores this file. |

### How tables are recognised

No table name, type number, column list or value is hardcoded here. A file is a
data table when its first record names columns and its second record carries
column types, where the type vocabulary is itself derived from the APK: a token
counts as a type only when it appears in the second record of at least two files.
Sectioned documents such as `level_0.csv` fail that test and are handled as
documents instead. A build whose shape does not match aborts the run instead of
producing a tree that guesses.

### The data-type registry

The client registers each data table under a type number and a name, and the
names ship XOR-encrypted in the library. `hd-dumper` recovers the registry with a
bounded pattern scan of `libg.so`: it decodes the text segment, collects the
calls into the registry's binder and the static initialisers beside them, and
decrypts the names those calls reference. It is a scan, not a decompilation: no
game logic is interpreted, and the result is rejected unless the binder was
found, the names decrypt to data-table paths, and the counts add up.

It reads the x86 library when the APK has one and the arm64-v8a library
otherwise:

- **x86** starts from build-1598 addresses (the binder, the initialiser and the
  key) and checks each by shape. For build 1598 it recovers 225 tables.
- **arm64-v8a** pins nothing to a build. Arguments travel in registers, so the
  binder is the call target that most often receives a global name slot, a
  constant type and a zero; the initialiser is the target that most often
  stores those slots; and the 128-byte key is rebuilt from the `data/` prefix
  every name shares, then has to occur verbatim in the library before it is
  used. On the arm64 library tested it recovers 226 tables, one more than the
  x86 scan. The extra one is probably type 1 (`languages`): its name slot is
  loaded about 450 instructions before its binder call, further back than the
  x86 scan's window reaches.

The numbers are ABI-independent, so an APK with neither library can reuse a map
produced from another (`--type-map`).

### What the spec holds

These facts are properties of the client's code, not of its data files, so they
come from `client-spec.toml` (an input, never a constant in this program; point
`--spec` elsewhere, or omit the file, to change or skip them):

| Spec key | Meaning | Provenance |
| --- | --- | --- |
| `[[walk]]` | the order generator's candidate tables, with their data-type numbers, in the client's own order | measured from a live client |
| `layout_types` | the data types the client allocates avatar bitsets for, in its own order | the client's phase-B bitset allocation |
| `unlock_default`, `[[unlock_row]]` | the `UnlockLevel` the client uses when a walked row's CSV cell is empty or absent, and its exceptions | the same live read |
| `money_type` | optional; only needed if the derived `money.csv` data type cannot be settled (a run reports what it found) | — |

Everything else in those files is derived, and the spec is checked: a walk whose
tail descends, or a layout list out of order, aborts the run rather than producing
a tree.

## What ships with the tool

Two files describe the client's wire interface rather than its data, and no
amount of CSV reading produces them:

| File | Carries |
| --- | --- |
| `command-schema.json` | the payload fields of every command type. |
| `command-evidence.json` | the analytics strings each command executor references. |

They live in `shipped/`, are copied into every generated tree, and are marked as
shipped (with their hashes) in the run report and in `sources.json`. See
[shipped/README.md](shipped/README.md) to supply your own.

## Tests

```sh
cargo test
```

Unit tests cover the CSV reader and the table rule. Run the integration suite
against your own APK — it checks the generated tree against the server's contract
(the registry resolving to real tables, the layout matching the starter's tables,
the level ladder, and the report for anything skipped):

```sh
HD_APK=/path/to/hayday.apk cargo test -- --ignored
```

The arm64 scan can also be checked against a bare library pulled from a device:

```sh
HD_LIBG_ARM64=/path/to/arm64/libg.so cargo test -- --ignored scans_a_real_library
```

`tools/compare-trees.py <generated> <reference>` checks one tree against another:
eight files byte for byte, `starter/layout.json` as parsed JSON, and every
reference entry in the three reduced tables unchanged.

## AI Usage

This project was almost exclusively written by AI, including the code, comments
and documentation. I reviewed everything, but since some people are uncomfortable
with AI-written code, I'm pointing it out.

### Details

- Deepseek V4.1 Flash 1017: everything — the extraction rules, the `libg.so`
  registry scan, the spec handling, the comparison tool, and this documentation
- Claude Haiku 5.5: some CLI work
- Human: review, testing against the server, and writing some of this README

It was run through [Hermes](https://github.com/NousResearch/hermes-agent) with a
shell, a Rust toolchain and `iced-x86` as the disassembler.
