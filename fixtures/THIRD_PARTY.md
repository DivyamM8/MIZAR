# Third-party test data

| Path | Source | Licence | Revision |
|---|---|---|---|
| `third_party/evtx/new-user-security.evtx`, `Security_short_selected.evtx`, `sysmon.evtx`, `sample_with_a_bad_chunk_magic.evtx` | https://github.com/omerbenamram/evtx (`samples/`) | Apache-2.0 (`third_party/evtx/LICENSE-APACHE`) | `370ecdba806eaafd14d618d6afcd609825a99762` |

SHA-256 of each file:

```
6f9fe51d0a5dec63dc68f819e23bc14da5db0b75db4a68dfdf6b39f02868a379  new-user-security.evtx
456d7645be38a8f72e9c9eb6c4fe42eac9c83d6ad34a9d039616af205e3bdc6f  sample_with_a_bad_chunk_magic.evtx
50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456  Security_short_selected.evtx
e1817fd7241ad2b5b9660e179adec878d157f1fa25333e52aef263c69bcd970b  sysmon.evtx
```

EVTX-ATTACK-SAMPLES was considered and not used: it is GPL-3.0, which is not
compatible with this project's Apache-2.0 licence (DESIGN.md D16, D21).
