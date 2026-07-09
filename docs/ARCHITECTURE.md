# comwatch architecture

comwatch is a small, deterministic pipeline. Text goes in; findings come out. No
live registry, no network, no persistent state — which is exactly what makes it
runnable on triage images, offline hives, and CI runners of any OS.

```
 .reg text ──► RegParser ──► List<RegEntry> ──► Detectors ──► List<Finding> ──► Reporters ──► stdout
                (parse)         (flat model)      (rules)        (dedup)          (format)
```

## Components

| File | Responsibility |
|------|----------------|
| `src/Model.cs`     | Core types: `Severity`, `RegEntry`, `Finding` (with a stable `Fingerprint`). |
| `src/RegParser.cs` | Clean-room parser for the `Windows Registry Editor Version 5.00` text format. Handles `@=`, named string values, `hex(2)`/`hex(7)` UTF-16LE decoding, `\`-continued lines, comments, `[-Key]` deletions, and hive classification. |
| `src/Detectors.cs` | Pure rule functions over `RegEntry` rows. Each rule maps to a MITRE ATT&CK technique and emits `Finding`s. De-duplicates by fingerprint. |
| `src/Reporters.cs` | Renders a `ScanResult` as JSON, SARIF 2.1.0, Sigma, CEF, or a console table. |
| `src/Program.cs`   | CLI: argument parsing, file/dir/stdin ingestion, baseline loading, severity thresholds, exit-code contract. |
| `src/Samples.cs`   | The synthetic `--selftest` export. |

## Design choices

- **Offline by construction.** The parser only reads text you hand it. There is
  no `RegistryKey` access anywhere in the codebase, so the tool is safe to run
  on a forensic image or in a Linux CI container.
- **Fingerprints, not line numbers, are the identity.** A finding's fingerprint
  is `SHA256(ruleId|hive|key|valueName|handler)[:16]`. This is stable across
  re-exports (line numbers change; the tradecraft doesn't), which is what makes
  baselining and SARIF `partialFingerprints` work.
- **Severity is a total order.** `Info < Low < Medium < High < Critical`. The
  `--min-severity` and `--fail-on` flags compare against it; INFO is hidden by
  default so a clean host reports nothing.
- **Reporters are additive.** Adding a format is one `switch` arm plus a method;
  the engine never changes.

## Exit-code contract

- `0` — no finding at or above `--fail-on` (default `high`).
- `2` — at least one finding at or above `--fail-on`. Gate CI/IR pipelines on this.
- `1` — usage or I/O error (bad flag, unreadable file, unknown format).

## Extending

Add a detector by appending a rule branch in `Detectors.Run`, calling `Add(...)`
with a severity, stable `ruleId`, ATT&CK technique, and tags. Add a test in
`tests/DetectorTests.cs`. That's it — reporters pick it up automatically.
