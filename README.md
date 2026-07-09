# comwatch

**COM-hijack & persistence detector (C# / .NET)** — find the registry tradecraft attackers hide in plain sight, from an offline `.reg` export.

[![ci](https://github.com/cognis-digital/comwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/comwatch/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C%23%20/%20.NET%208-512BD4)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)**.

## The problem

COM hijacking, IFEO debuggers, AppInit_DLLs, COR_PROFILER, Run keys — the most durable Windows persistence lives in the registry, and it's easy to miss by eye across a triage image. comwatch parses a **registry export** (`reg export …`) instead of a live registry, so the same tool runs on:

- an analyst's workstation against a captured hive,
- a forensic image with no live host, and
- a Linux/macOS CI runner as a gate on a golden image.

It maps every finding to **MITRE ATT&CK**, emits **JSON / SARIF 2.1.0 / Sigma / CEF / table**, and returns a CI-friendly exit code. No live registry access, no network, no state.

## Detections (14 rules across 8 ATT&CK techniques)

| Rule | ATT&CK | Catches |
|---|---|---|
| `com-hijack` | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | CLSID handler in **HKCU/HKCR** overriding the system COM object |
| `com-handler-user-writable` | T1546.015 | COM handler resolving into AppData/Temp/ProgramData/… |
| `com-handler-lolbin` | [T1218](https://attack.mitre.org/techniques/T1218/) | COM handler invoking rundll32/regsvr32/mshta/powershell/… |
| `com-treatas` | T1546.015 | CLSID `TreatAs` redirection to another class |
| `com-scriptlet` | T1218 | `ScriptletURL`/`Moniker` (scrobj) COM objects |
| `shell-verb-hijack` | T1546.015 | user-hive `shell\open\command` invoking a LOLBin |
| `autorun` | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `Run`/`RunOnce`/`RunServices` persistence |
| `ifeo-debugger` / `ifeo-silentexit` | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | IFEO `Debugger` / `SilentProcessExit` hijacks |
| `appinit-dlls` | [T1546.010](https://attack.mitre.org/techniques/T1546/010/) | populated `AppInit_DLLs` |
| `cor-profiler` | [T1574.012](https://attack.mitre.org/techniques/T1574/012/) | `COR_PROFILER` .NET profiler injection |
| `winlogon-tamper` | [T1112](https://attack.mitre.org/techniques/T1112/) | Winlogon `Shell`/`Userinit` tampering |
| `service-imagepath` | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | service binary in a user-writable dir / LOLBin |

Full reference: [`docs/DETECTIONS.md`](docs/DETECTIONS.md).

## Quick start

```bash
dotnet build -c Release
dotnet run -c Release -- --selftest              # analyze the bundled sample
dotnet run -c Release -- export.reg              # analyze a real export
dotnet run -c Release -- export.reg --format sarif   # emit SARIF for code scanning
reg export HKCU\Software\Classes\CLSID hkcu.reg && dotnet run -c Release -- hkcu.reg
```

## Example output (real, captured from `--selftest`)

Running the bundled self-test with the human-readable table format:

```
$ comwatch --selftest --format table -q
comwatch 2.0.0 — source: <selftest>
findings: 10  (HIGH+: 9)
------------------------------------------------------------------------------
[HIGH    ] com-hijack  (T1546.015)
    COM server registered in a user-controlled hive
    key    : HKEY_CURRENT_USER\Software\Classes\CLSID\{0002DF01-...-000000000046}\InprocServer32
    handler: C:\Users\victim\AppData\Roaming\evil.dll

[HIGH    ] com-treatas  (T1546.015)
    CLSID TreatAs redirection
    key    : HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-...-555555555555}\TreatAs
    handler: {99999999-8888-7777-6666-555555555555}

[HIGH    ] ifeo-debugger  (T1546.012)
    Image File Execution Options debugger
    key    : ...\CurrentVersion\Image File Execution Options\sethc.exe
    value  : Debugger
    handler: C:\Windows\System32\cmd.exe

[HIGH    ] appinit-dlls  (T1546.010)
    AppInit_DLLs injection
    handler: C:\ProgramData\inject.dll

[HIGH    ] cor-profiler  (T1574.012)   [HIGH] winlogon-tamper  (T1112)
[HIGH    ] service-imagepath (T1543.003)   ... (10 findings total)
```

Default output is JSON (one finding shown):

```json
{
  "tool": "comwatch",
  "version": "2.0.0",
  "source": "<selftest>",
  "finding_count": 10,
  "high_count": 9,
  "severity_breakdown": { "HIGH": 9, "MEDIUM": 1 },
  "findings": [
    {
      "severity": "HIGH",
      "id": "com-hijack",
      "title": "COM server registered in a user-controlled hive",
      "technique": "T1546.015",
      "technique_name": "Event Triggered Execution: Component Object Model Hijacking",
      "hive": "HKCU",
      "clsid": "{0002DF01-0000-0000-C000-000000000046}",
      "key": "HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0002DF01-0000-0000-C000-000000000046}\\InprocServer32",
      "handler": "C:\\Users\\victim\\AppData\\Roaming\\evil.dll",
      "line": 9,
      "tags": ["com", "persistence", "hijack"],
      "fingerprint": "91fa94b6408ac42f"
    }
  ]
}
```

A clean export reports nothing and exits 0:

```
$ comwatch examples/clean.reg -q
{ "tool": "comwatch", "version": "2.0.0", "source": "examples/clean.reg",
  "finding_count": 0, "high_count": 0, "severity_breakdown": {}, "findings": [] }
$ echo $?
0
```

## CLI

```
comwatch <path...>          analyze .reg file(s) or directories (recursive)
comwatch -                  read a .reg export from stdin
comwatch --selftest         analyze the bundled sample export

--format <fmt>              json | sarif | sigma | cef | table   (default json)
--min-severity <level>      report only findings >= level
--include-info              include INFO baseline findings
--baseline <file>           suppress fingerprints listed in <file>
--fail-on <level>           exit 2 when any finding >= level (default high)
-q, --quiet                 suppress the human summary on stderr
```

**Exit codes:** `0` clean · `2` finding at/above `--fail-on` · `1` usage/IO error. Gate CI/IR pipelines on it.

## Formats

- **JSON** — structured report with `findings[]`, severity breakdown, and a stable per-finding `fingerprint`.
- **SARIF 2.1.0** — upload to GitHub code scanning or open in the VS Code SARIF viewer. Includes rule metadata, ATT&CK `helpUri`s, and `partialFingerprints`.
- **Sigma** — a ready-to-tune detection rule for the CLSID hijacks found (`registry_set` logsource).
- **CEF** — ArcSight Common Event Format, one line per finding, for SIEM ingest.
- **table** — human-readable console output for triage.

## Install

### Linux / macOS
```sh
./install.sh                 # builds a self-contained binary into ~/.local/bin
comwatch --selftest
```

### Windows (PowerShell)
```powershell
./install.ps1                # builds into %LOCALAPPDATA%\Programs\comwatch and adds to PATH
comwatch --selftest
```

### Docker
```sh
docker build -t comwatch .
docker run --rm -v "$PWD:/work" comwatch /work/export.reg --format sarif
```

### From source (any OS with the .NET 8 SDK)
```sh
make build && make test && make demo
```

## Tests & demo

```sh
dotnet test tests/ComWatch.Tests.csproj    # 32 xUnit tests (parser, detectors, reporters)
bash examples/demo.sh                       # runnable end-to-end demo
```

The test suite covers the parser (string/hex/continuation/hive classification), every detector (positive and negative cases, baseline suppression, fingerprint stability), and every reporter (valid JSON/SARIF, Sigma tags, CEF headers, exit-code contract). CI builds and runs the full suite on **Ubuntu, Windows, and macOS**.

## Architecture

`.reg text → RegParser → RegEntry[] → Detectors → Finding[] → Reporters → stdout`. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Scope

Defensive triage only. Use comwatch on systems and data you own or are explicitly authorized to examine. See [`DISCLAIMER.md`](DISCLAIMER.md).

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
