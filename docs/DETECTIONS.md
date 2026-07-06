# comwatch detections

Every rule maps to a MITRE ATT&CK technique. Rules are pure functions over the
parsed `.reg` export — comwatch never reads a live registry.

| Rule id | Severity | ATT&CK | What it catches |
|---------|----------|--------|-----------------|
| `com-hijack` | HIGH | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | A CLSID `InprocServer32`/`LocalServer32`/`InprocHandler32` handler registered in **HKCU/HKCR**. The user hive takes precedence over HKLM, so this silently overrides the system COM object. |
| `com-handler-user-writable` | HIGH | T1546.015 | A COM handler DLL/EXE that resolves into a user-writable directory (AppData, Temp, ProgramData, Public, Downloads, Roaming, PerfLogs). |
| `com-handler-lolbin` | HIGH | [T1218](https://attack.mitre.org/techniques/T1218/) | A COM handler that invokes a living-off-the-land binary (rundll32, regsvr32, mshta, powershell, wscript, certutil, …). |
| `com-treatas` | HIGH / MED | T1546.015 | A CLSID `TreatAs` value re-points one class to another. HIGH in a user hive, MEDIUM in HKLM. |
| `com-scriptlet` | HIGH | T1218 | A CLSID with a `ScriptletURL`/`Moniker` value (scrobj.dll surrogate) that executes script as a COM object. |
| `shell-verb-hijack` | HIGH | T1546.015 | A user-hive `...\shell\<verb>\command` that invokes a LOLBin or user-writable payload — hijacks the handler for a file/protocol class. |
| `autorun` | HIGH / MED / INFO | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `Run`/`RunOnce`/`RunServices` values. HIGH if LOLBin or user-writable; INFO for signed system-path entries; MEDIUM otherwise. |
| `ifeo-debugger` | HIGH | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | An Image File Execution Options `Debugger` value hijacks a target image (e.g. `sethc.exe`). |
| `ifeo-silentexit` | HIGH | T1546.012 | A `SilentProcessExit\MonitorProcess` value launches a binary when a monitored process exits. |
| `appinit-dlls` | HIGH | [T1546.010](https://attack.mitre.org/techniques/T1546/010/) | A populated `AppInit_DLLs` value — every GUI process loads the listed DLL(s). |
| `cor-profiler` | HIGH / MED | [T1574.012](https://attack.mitre.org/techniques/T1574/012/) | `COR_PROFILER` / `COR_PROFILER_PATH` / `COR_ENABLE_PROFILING` values force a profiler DLL into managed processes. |
| `winlogon-tamper` | HIGH | [T1112](https://attack.mitre.org/techniques/T1112/) | A Winlogon `Shell`/`Userinit` value that deviates from the pristine `explorer.exe` / `userinit.exe`. |
| `service-imagepath` | HIGH | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | A service `ImagePath` that resolves to a user-writable directory or a LOLBin. |
| `com-server` | INFO | T1546.015 | A benign HKLM COM server registration (baseline; hidden unless `--include-info`). |

## Tuning

- `--min-severity <level>` filters output at or above a level.
- `--fail-on <level>` sets the exit-2 threshold (default `high`).
- `--baseline <file>` suppresses specific findings by fingerprint. Produce
  fingerprints once from a known-good host, drop them (one per line) into a file,
  and comwatch will stop reporting them.

## What comwatch does NOT do

- It does not read or modify a live registry.
- It does not remediate. It reports; you decide.
- The live-vs-baseline decision on paths is heuristic — a `com-server` INFO can
  still be malicious if the DLL path is wrong for that CLSID. Treat comwatch as a
  triage lead, not a verdict.
