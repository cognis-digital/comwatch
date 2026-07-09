// comwatch — bundled sample export for --selftest and tests
// Part of the Cognis Neural Suite. Defensive triage only.
//
// A synthetic .reg export that exercises the detector suite end-to-end. All
// values are fabricated for demonstration; no real key material or live host.
namespace ComWatch;

public static class Samples
{
    public static string SelfTest() =>
@"Windows Registry Editor Version 5.00

; benign HKLM COM server (baseline — INFO only, hidden unless --include-info)
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\InprocServer32]
@=""C:\\Windows\\System32\\ieframe.dll""

; malicious HKCU COM hijack pointing at AppData (com-hijack + com-handler-user-writable)
[HKEY_CURRENT_USER\Software\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\InprocServer32]
@=""C:\\Users\\victim\\AppData\\Roaming\\evil.dll""

; TreatAs redirection in HKCU (com-treatas)
[HKEY_CURRENT_USER\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\TreatAs]
@=""{99999999-8888-7777-6666-555555555555}""

; autorun via LOLBin in a user-writable path (autorun, HIGH)
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
""Updater""=""rundll32.exe C:\\Users\\victim\\AppData\\Local\\Temp\\x.dll,Start""

; Image File Execution Options debugger hijack (ifeo-debugger, HIGH)
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe]
""Debugger""=""C:\\Windows\\System32\\cmd.exe""

; AppInit_DLLs injection (appinit-dlls, HIGH)
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
""AppInit_DLLs""=""C:\\ProgramData\\inject.dll""

; COR_PROFILER .NET profiler hijack (cor-profiler)
[HKEY_CURRENT_USER\Environment]
""COR_ENABLE_PROFILING""=""1""
""COR_PROFILER_PATH""=""C:\\Users\\victim\\AppData\\Local\\Temp\\prof.dll""

; Winlogon Shell tampering (winlogon-tamper, HIGH)
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
""Shell""=""explorer.exe, C:\\Users\\victim\\AppData\\Roaming\\backdoor.exe""

; Service ImagePath in a user-writable dir (service-imagepath, HIGH)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EvilSvc]
""ImagePath""=""C:\\ProgramData\\svc\\payload.exe""
";
}
