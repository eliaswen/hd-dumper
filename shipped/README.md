# Shipped protocol tables

Two files the server loads cannot be derived from an APK's data files, because
they describe the client's *wire* interface rather than its data:

| File | Carries | Origin |
| --- | --- | --- |
| `command-schema.json` | the payload fields of every command type, keyed by command type | decoded from the build-1598 x86 command factories behind the decoder's switch jump table |
| `command-evidence.json` | the analytics strings each command executor references | decoded from the build-1598 x86 command executors, whose literals ship encrypted in the library's `.data` |

`hd-dumper` copies both into every tree it generates, so a generated tree is
complete; `sources.json` records their hashes, and the run report marks them as
shipped rather than derived from your APK.

They are interface facts: the boundaries of each message's payload and the labels
the client logs for it. See [LEGAL.md](../LEGAL.md) for the legal position, which
the project relies on deliberately.

## Using your own

```sh
hd-dumper --apk hayday.apk --out resources --shipped /path/to/my/tables
```

Both files are plain JSON objects keyed by command type. `hd-dumper` parses each
and refuses to write a tree if one is missing or is not a non-empty object; with
no `--shipped` directory the two files are reported as skipped instead.
