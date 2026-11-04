# MIZAR user guide

MIZAR is a log analyzer for security investigations. It runs on your own
computer, takes the logs you collected, puts them into one common format,
runs detection rules over them, and helps you check each lead against the
original records. It then produces a report you can hand over.

MIZAR is not a SIEM, an EDR or a packet analyzer. It does not collect logs,
watch systems live, or read network captures. It works on log files you give
it.

Contents:

1. [Install, start and stop](#1-install-start-and-stop)
2. [The workflow at a glance](#2-the-workflow-at-a-glance)
3. [Cases](#3-cases)
4. [Adding evidence](#4-adding-evidence)
5. [Running an analysis](#5-running-an-analysis)
6. [Reviewing findings](#6-reviewing-findings)
7. [Timeline, events, entities and sessions](#7-timeline-events-entities-and-sessions)
8. [Reports and exports](#8-reports-and-exports)
9. [Evidence integrity](#9-evidence-integrity)
10. [Your data: location, backup and removal](#10-your-data-location-backup-and-removal)
11. [Settings](#11-settings)
12. [Troubleshooting](#12-troubleshooting)
13. [Limitations](#13-limitations)

---

## 1. Install, start and stop

You need Python 3.13 or newer on Linux or macOS. To build MIZAR from a source
checkout you also need Node.js 20 or newer.

**Install** (from the source checkout):

```bash
scripts/install.sh
```

This builds MIZAR and installs it with the dependency versions it was tested
with. It goes into its own environment in `~/.local/share/mizar-app`, and the
`mizar` command is linked into `~/.local/bin`. Run the same command again to
upgrade. Your cases are not touched.

If you already use `pipx`, you can instead run `scripts/build.sh` and then
`pipx install dist/mizar-*.whl`.

**Start:**

```bash
mizar serve
```

Then open http://127.0.0.1:8730 in your browser. MIZAR can only be reached
from this computer; it refuses to listen on a network address.

**Stop:** press Ctrl+C in the terminal running `mizar serve`, or stop the
process normally (`kill <pid>`). Background work that was interrupted resumes
the next time you start MIZAR.

**Version:** `mizar --version`.

---

## 2. The workflow at a glance

1. **Create a case** for the investigation.
2. **Upload evidence**, the log files or archives, with timezone and year
   hints where the logs need them.
3. **Check the evidence page**: was each file recognized, and did it parse
   cleanly?
4. **Run an analysis.** Every rule runs over every event, after the evidence
   hashes are re-checked.
5. **Review findings.** For each one, read why it was raised, look at the
   supporting events and their original records, then set a status and add
   notes.
6. **Use the timeline, entities and sessions** to follow activity around a
   finding.
7. **Export a report**: a PDF to share, and JSON or CSV for your own records
   and tools.

---

## 3. Cases

A case holds everything for one investigation: evidence, events, analysis
runs, findings, your notes and the exports.

- **Create:** on the Cases page, enter a name and the analyst's name. A
  reference (ticket or incident number) and a description are optional. The
  analyst name is recorded on runs, status changes and reports.
- **Default timezone:** a case can have a default timezone. It is used for
  uploaded logs whose times have no offset, unless you give a different one
  for a file.
- **Edit:** on the case's Overview page.
- **Delete:** at the bottom of the Overview page, by typing the exact case
  name. This permanently removes the case's database records, its exports and
  its copies of the evidence. Evidence content that another case also holds
  is kept for that case. Deletion is refused while a job for the case is
  running.

The tabs across the top of a case are the sections of the investigation:
Overview, Evidence, Findings, Timeline, Events, Entities, Sessions, Runs and
Reports.

---

## 4. Adding evidence

Open the **Evidence** tab and drop files onto the upload area, or choose them.
Several files can be uploaded at once.

### Supported formats

| Area | Formats |
|---|---|
| Windows | `.evtx` files; events exported as XML (wevtutil), JSON (Get-WinEvent) or CSV (Event Viewer) |
| Linux | syslog (traditional and RFC 5424, including `auth.log`, `secure`, `messages`, `kern.log` with iptables, UFW or firewalld lines), journald JSON export, auditd |
| Web and network | Apache/Nginx access logs, Zeek (TSV and JSON), CEF, LEEF, Squid |
| Archives | zip, tar, gzip, bzip2, xz (nested up to 3 levels), unpacked automatically |

MIZAR detects the format from the content, not from the file name. The
evidence page shows which format was chosen and how confident the detection
was. A file it cannot recognize is still kept and read with a generic parser,
which extracts only basic fields. Such files are listed as **coverage gaps**.
If the detection was wrong, choose the right format and **Re-parse** the file.

Windows exports without field names (Get-WinEvent JSON with positional
properties, Event Viewer CSV) give the event meaning but not the account or
address fields. Those events are marked `partial`.

### Timezone and year hints

Many logs record times without saying which timezone they are in, and classic
syslog does not even record the year. MIZAR never guesses either.

- **Timezone of logs without an offset:** the timezone the logging host used,
  e.g. `Europe/Berlin` or `UTC`. Without it, such events get no UTC time.
- **Year of the first record:** needed for classic syslog. Later records that
  pass New Year are given the next year, and the event is flagged so you can
  check.

Events without a reliable UTC time are not lost. They appear in their own
lane of the timeline, in file order, and are left out of time-window rules.
The overview and the reports say how many there are. To place them, set the
hints on the file and **Re-parse** it.

Times that are ambiguous because of a daylight-saving change (the repeated or
skipped hour) are also left without a UTC time, rather than guessed.

### What happens to an upload

1. The file is stored unchanged in the evidence store and its SHA-256 is
   computed. The original name, size and upload time are recorded.
2. Archives are unpacked. Each member becomes its own evidence file, linked to
   the archive it came from. Unsafe members (paths leaving the archive, links,
   devices) and suspected archive bombs are refused and recorded; the other
   members continue.
3. Each file is parsed into events. The evidence page shows how many records
   parsed fully, partially or not at all, with the reasons.

The same record collected in two files (for example an overlapping rotated
log) is kept in both and grouped as a duplicate. Rules count it once.

---

## 5. Running an analysis

Click **Run analysis** on the Overview or Runs tab. It is available once every
upload has finished parsing.

A run:

1. re-checks every evidence file against its recorded SHA-256 and stops if
   any file changed;
2. runs every detection rule (see the **Rules** page in the top bar for what
   each rule looks for and its parameters);
3. records a **manifest**: the inputs and their hashes, the parser and rule
   versions, the parameters, and the results.

Runs are reproducible. Two runs with the same **inputs fingerprint** used the
same evidence, parsers, rules and parameters, and produced the same findings.

**Parameter overrides:** on the Runs tab you can change a rule's thresholds
for one run, for example a lower failure count for a brute-force rule. The
override is recorded in that run's manifest.

**Comparing runs:** select two runs on the Runs tab to see which findings are
new, gone or changed between them.

If you add or re-parse evidence after a run, run the analysis again. Earlier
runs keep their own results.

---

## 6. Reviewing findings

The **Findings** tab lists the findings of the latest run (choose another run
with the run selector). They are sorted by severity, then confidence, then
evidence strength, then first observed time.

Three ratings are kept separate on purpose:

| Rating | Question it answers |
|---|---|
| **Severity** (Informational, Low, Medium, High, Critical) | How serious would this be if it is what the rule describes? |
| **Confidence** (Low, Medium, High) | How likely is that interpretation, given the records? |
| **Evidence strength** (direct, corroborated, circumstantial, inferred) | How directly do the records show it? |

A finding is a lead, not a conclusion. Each finding page lists:

- the **rationale** for its severity and confidence;
- what was **observed**: event counts and the most frequent values;
- the **interpretation**, which is a hypothesis;
- **alternative explanations**, the benign or other causes to rule out;
- **verification steps**, what to check next;
- the **source files** with their hashes;
- **related findings**, for findings that chain other findings;
- the **supporting events**. Click one to open the event panel with the
  original record.

### The event panel

Clicking an event anywhere opens a panel with all its fields and its
**original record**. A record read back from the evidence file shows whether
it still **matches its hash**. The panel also shows the event's sessions and
duplicates, links documented by the log itself (Sysmon process GUIDs), and
related events. Related events share an IP, user or host within a time
window, which is a similarity, not proof of cause.

### Status and notes

Under **Analyst review**, set the status and write notes:

| Status | Use it when |
|---|---|
| Open | Not reviewed yet (the default) |
| Investigating | You are working on it |
| Confirmed | You verified the activity is what the finding describes |
| False positive | You verified it is benign or wrong |
| Resolved | Dealt with |

Status and notes carry over to the matching finding of a later run, and the
finding then says it was carried over. Reports show the status and notes at
the time the report is made.

---

## 7. Timeline, events, entities and sessions

- **Timeline:** every event in UTC order, with a histogram you can click to
  zoom in. You can filter by host, user, IP, event type, finding or minimum
  severity. Rows with findings are marked. Events without a reliable UTC time
  have their own lane (**Without reliable time**).
- **Events:** search and filter all events, including a text search.
- **Entities:** the hosts, users and IP addresses seen, with how often, when,
  and which findings name them.
- **Sessions:** events that share a host and session or logon ID. A session
  is split when there is a gap of more than 8 hours. Shared system logon IDs
  are excluded.

All times are shown in UTC with a `Z`, next to the original timestamp text,
never in your browser's timezone. Filters are part of the page address, so a
view survives a reload and can be bookmarked.

---

## 8. Reports and exports

Open the **Reports** tab, choose a finished run, then choose a format:

| Format | Contents | Use it for |
|---|---|---|
| **PDF report** | Cover with case and run details and hashes; executive summary; evidence files with SHA-256 and parse statistics; methodology; one section per finding with every field and its supporting events; timeline; entities; limitations; run manifest | Reading and sharing |
| **JSON** | The full run manifest, source files, findings, and every referenced event with its original record (hash-checked) | Records and your own tools |
| **CSV (ZIP)** | `findings.csv`, `events.csv`, `source_files.csv` and `export.json` | Spreadsheets |

Options:

- **Include findings with status:** for example, leave out false positives.
  The summary says how many findings were left out.
- **Minimum severity.**
- **Marking** (PDF): **Draft** or **Final**, printed on every page.
- **Supporting events shown per finding** (PDF, default 10). The JSON and CSV
  exports always contain the complete lists.
- **Include every event** (JSON, CSV): adds all events of the run's files, not
  only the supporting ones. JSON then becomes a ZIP with `report.json` and
  `events.ndjson`.

Exports are made in the background; the list shows their progress. When one
is ready, **Download** it. Record the **SHA-256** shown next to it, so the
file you hand over can be identified later. Each export reflects finding
statuses at the moment it was made, and states that time.

About text in the PDF:

- Log text is printed exactly as text. Anything that looks like markup is
  shown literally.
- Latin, Cyrillic, Greek and many other scripts are drawn normally.
- These are shown as escapes like `\u{4e2d}`: characters the report fonts
  lack (for example Chinese, Japanese and Korean), right-to-left scripts (the
  PDF could not show them in reading order), and invisible characters that
  can disguise text, such as the right-to-left override in
  `invoice\u{202e}fdp.exe`. Control characters appear as `\x07` and similar.
  The JSON export has the exact text.

In the CSV files, any value a spreadsheet would run as a formula (starting
with `=`, `+`, `-`, `@`, tab or carriage return) is prefixed with `'`.

---

## 9. Evidence integrity

- Every uploaded file is stored unchanged and read-only, under its SHA-256.
- **Verify evidence hashes** on the Overview tab (or **Verify all hashes** on
  the Evidence tab) re-hashes every file of the case. Every analysis run does the same first.
- If a file no longer matches its hash, the file is marked
  `integrity_failed` and analysis runs are refused. Treat this as a problem
  with the storage or the computer: don't keep working with that copy. Upload
  the evidence again from your original source into a new case.
- Original records shown in the event panel and written to the JSON export
  are read back from the evidence file and checked against the record's hash.

---

## 10. Your data: location, backup and removal

All cases live in the data directory, `~/.local/share/mizar` by default (set
`MIZAR_DATA_DIR` to change it). It contains:

- the database (`mizar.db`);
- the evidence store (`evidence/`);
- the exports (`exports/`).

It is created readable only by you. MIZAR warns at start-up if other users
can access it.

It holds case evidence. Keep it on encrypted storage, and keep it out of
synced folders and source repositories.

**Backup:** stop MIZAR, then copy the whole data directory. The database is
only consistent when copied while MIZAR is stopped.

**Uninstall:** remove `~/.local/share/mizar-app` and `~/.local/bin/mizar`.
That leaves your cases in place; delete the data directory as well to remove
them.

---

## 11. Settings

Settings are environment variables, read when MIZAR starts.

| Variable | Default | Meaning |
|---|---|---|
| `MIZAR_DATA_DIR` | `~/.local/share/mizar` | Where cases are stored |
| `MIZAR_PORT` | `8730` | Port on 127.0.0.1 |
| `MIZAR_MAX_FILE_BYTES` | 2 GiB | Largest single upload |
| `MIZAR_MAX_CASE_UNCOMPRESSED_BYTES` | 20 GiB | Largest case after unpacking archives |
| `MIZAR_MAX_ARCHIVE_MEMBERS` | 10,000 | Members unpacked per archive |
| `MIZAR_MAX_ARCHIVE_DEPTH` | 3 | Nesting levels unpacked |
| `MIZAR_MAX_COMPRESSION_RATIO` | 100 | Compression ratio treated as an archive bomb (for members over 10 MiB) |
| `MIZAR_MIN_FREE_DISK_BYTES` | 1 GiB | Free disk space kept; uploads stop before going below it |
| `MIZAR_JOB_TIMEOUT_SECONDS` | 21600 (6 hours) | A background job running longer is stopped (see Troubleshooting) |
| `MIZAR_LOG_LEVEL` | `INFO` | Detail of the application log (JSON lines on the terminal) |

Example: `MIZAR_PORT=8800 mizar serve`.

---

## 12. Troubleshooting

| What you see | Meaning and what to do |
|---|---|
| The page says the web UI has not been built | You are running from a source checkout without a built UI. Run `scripts/install.sh`, or `cd frontend && npm ci && npm run build` |
| Address already in use when starting | Another program (or another MIZAR) uses port 8730. Stop it, or start with `MIZAR_PORT=8800 mizar serve` |
| "Missing or invalid API token" | MIZAR was restarted while the page was open. Reload the page |
| "MIZAR is not reachable" | `mizar serve` is not running |
| **Run analysis** says evidence is still being processed | Wait until the uploads finish parsing (Evidence tab) |
| A run fails with `EVIDENCE_INTEGRITY_MISMATCH` | An evidence file changed on disk. See [Evidence integrity](#9-evidence-integrity) |
| An upload fails with `FILE_TOO_LARGE` or `CASE_BUDGET_EXCEEDED` | It is over the limits in [Settings](#11-settings). Split the evidence, or raise the limit |
| `STORAGE_FULL` | The disk is nearly full. Free space, or move the data directory |
| A file shows **unsupported**, or the generic parser | The content was not recognized. Choose the format and **Re-parse**, or treat the file as a coverage gap |
| Many events are **Unplaced** | They had no timezone or year. Set the hints and **Re-parse** |
| A job failed with `JOB_TIMEOUT` | It ran longer than `MIZAR_JOB_TIMEOUT_SECONDS`, usually because of malformed input, so it was stopped and the background worker restarted. Other jobs carry on. For a genuinely huge file, raise the limit and re-parse |
| A job failed with `JOB_CRASHED` | The worker stopped unexpectedly several times on this job. Check the terminal log for the job ID |
| Deleting a case is refused | A job for the case is running. Cancel it, or wait |

The application log in the terminal has one JSON line per event, with
`job_id`, `case_id` and `request_id` fields. Error messages in the UI include a
request ID to look up there.

---

## 13. Limitations

- MIZAR reports what the collected logs contain. Activity that was not logged,
  logs that were not collected, and techniques no rule covers do not appear.
- Clock differences between hosts are not corrected.
- macOS unified logs and generic JSON/CSV field mapping are not supported yet.
  Such files are read with the generic parser.
- One analyst on one computer: there are no user accounts or sharing.
- Speed on a typical laptop: parsing runs at about 14,000 events per second,
  so a 2 GB case of about 13 million events takes roughly a quarter of an
  hour. An analysis run over 10 million events takes several minutes.
  Exports stream at about 30,000 events per second.
