# comwatch

**COM-hijack & persistence detector (C# / .NET)** — find the registry tradecraft attackers hide in plain sight.

[![ci](https://github.com/cognis-digital/comwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/comwatch/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C%23-512BD4)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)**. `comwatch` parses a Windows registry export (`reg export ...`) — **no live registry access**, so it runs on triage images, exported hives, and CI — and flags persistence/hijack tradecraft:

| Finding | Why it matters | ATT&CK |
|---|---|---|
| **COM hijack** | a CLSID `InprocServer32`/`LocalServer32` handler in **HKCU** silently overrides the system (HKLM) COM object | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) |
| **User-writable handler** | COM handler DLL/EXE resolves into AppData/Temp/Public/ProgramData | T1546.015 |
| **LOLBin handler** | handler invokes rundll32/regsvr32/mshta/powershell/wscript… | [T1218](https://attack.mitre.org/techniques/T1218/) |
| **Autorun** | `...\CurrentVersion\Run` / `RunOnce` persistence values | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |

It emits structured JSON **or a ready-to-deploy Sigma rule** for the hijacked CLSIDs it finds. Defensive triage only.

## Build / run

```bash
dotnet build -c Release
dotnet run -- --selftest                 # demo on a bundled sample export
comwatch export.reg                       # analyze a real export
comwatch export.reg --format sigma        # emit a Sigma detection rule
reg export HKCU\Software\Classes\CLSID hkcu_clsid.reg && comwatch hkcu_clsid.reg
```

## Output

JSON with a `findings[]` array (severity / id / MITRE technique / hive / clsid / handler). Exit **2** if any HIGH finding, else **0** — gate CI / IR pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
