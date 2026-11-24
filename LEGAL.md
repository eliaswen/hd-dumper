# Legal notice

This project is provided for interoperability, research and preservation, and
comes with no warranty (see [LICENSE](LICENSE)).

You are responsible for complying with the laws that apply to you, including
copyright, the software's terms of service, and rules on circumventing
technical protection measures. In particular:

- Only use it with an APK you are entitled to use.
- Do not redistribute the data this tool extracts from an APK.
- Do not use it to access services you are not authorized to use.
- Do not use it against a third party's servers.

## Supercell Terms of Service

This project is not affiliated with, endorsed by or sponsored by Supercell.
Using it is not compatible with the
[Supercell Terms of Service](https://supercell.com/en/terms-of-service/), which
prohibit reverse engineering and modifying the game client, among other things.
Using it is entirely at your own risk.

"Hay Day" and "Supercell" are trademarks of their respective owners and are
used here only to describe what this tool is compatible with.

## No game data

This repository contains no game data and no APKs. The tool reads the APK you
supply and writes the extracted tables to the output directory you choose. Keep
that output — and any copy of an APK — to yourself.

One exception, and it is deliberate: `shipped/` holds two tables that describe
the client's *wire* interface rather than its content — which fields a message of
each type carries, and the strings the client logs for each command. Neither can
be recovered from the APK's data files, so they travel with the tool instead of
being regenerated from your copy. Point `--shipped` elsewhere, or delete the
directory, to build without them.

## Functionality, interfaces and data formats

EU law distinguishes a program's protected expression from what the program does.
In *SAS Institute Inc v World Programming Ltd* (C‑406/10, judgment of 2 May 2012)
the Court of Justice of the European Union held that the copyright in a computer
program does not extend to its functionality, its programming language or its
data-file formats: none of those is a form of expression the copyright protects,
so reproducing them is not by itself an infringement. That is the distinction
this project relies on. What it extracts is interface: the data-type number a
table is registered under, the boundaries of each command's payload, the columns
and rows of the game's own data tables, and the bootstrap and login envelopes.

The protection that remains is untouched here — the library's own code, its
artwork, audio and the game's expressive content are not copied, and no APK is
redistributed. Note also that the ruling decided a different set of facts, that
the scope of protection is ultimately a question for the courts, and that the
game's terms of service prohibit reverse engineering regardless of copyright
(see above). None of this is legal advice, and using this project remains your
own responsibility.

## Cheating

This project is not a cheating tool and must not be used as one. It extracts
data tables so that a server you run yourself can serve a client you patched
yourself. It does not change game logic, grant resources or give any advantage
on Supercell's official servers.
