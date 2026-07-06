// comwatch — detector unit tests
using ComWatch;
using Xunit;

namespace ComWatch.Tests;

public class DetectorTests
{
    static List<Finding> Scan(string reg, DetectorOptions? o = null)
        => Detectors.Run(RegParser.Parse(reg), o);

    [Fact]
    public void Detects_Hkcu_Com_Hijack()
    {
        var f = Scan("[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{A}\\InprocServer32]\n@=\"c:\\\\windows\\\\x.dll\"\n");
        Assert.Contains(f, x => x.RuleId == "com-hijack" && x.Severity == Severity.High);
    }

    [Fact]
    public void Detects_User_Writable_Handler()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{A}\\InprocServer32]\n@=\"C:\\\\Users\\\\v\\\\AppData\\\\Roaming\\\\e.dll\"\n");
        Assert.Contains(f, x => x.RuleId == "com-handler-user-writable");
    }

    [Fact]
    public void Detects_Lolbin_Handler()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{A}\\LocalServer32]\n@=\"regsvr32.exe /s x.dll\"\n");
        Assert.Contains(f, x => x.RuleId == "com-handler-lolbin" && x.Technique == "T1218");
    }

    [Fact]
    public void Benign_Hklm_Com_Server_Is_Info_And_Hidden_By_Default()
    {
        var reg = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{A}\\InprocServer32]\n@=\"C:\\\\Windows\\\\System32\\\\ok.dll\"\n";
        Assert.Empty(Scan(reg)); // INFO suppressed by default
        var withInfo = Scan(reg, new DetectorOptions { IncludeInfo = true });
        Assert.Contains(withInfo, x => x.RuleId == "com-server" && x.Severity == Severity.Info);
    }

    [Fact]
    public void Detects_TreatAs_Redirection()
    {
        var f = Scan("[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{A}\\TreatAs]\n@=\"{B}\"\n");
        Assert.Contains(f, x => x.RuleId == "com-treatas");
    }

    [Fact]
    public void Detects_Autorun_LOLBin_As_High()
    {
        var f = Scan("[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"U\"=\"rundll32.exe x.dll,Go\"\n");
        var a = Assert.Single(f, x => x.RuleId == "autorun");
        Assert.Equal(Severity.High, a.Severity);
    }

    [Fact]
    public void Detects_Ifeo_Debugger()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe]\n\"Debugger\"=\"cmd.exe\"\n");
        Assert.Contains(f, x => x.RuleId == "ifeo-debugger" && x.Technique == "T1546.012");
    }

    [Fact]
    public void Detects_AppInit_Dlls()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows]\n\"AppInit_DLLs\"=\"c:\\\\x.dll\"\n");
        Assert.Contains(f, x => x.RuleId == "appinit-dlls" && x.Technique == "T1546.010");
    }

    [Fact]
    public void Detects_Cor_Profiler()
    {
        var f = Scan("[HKEY_CURRENT_USER\\Environment]\n\"COR_PROFILER_PATH\"=\"C:\\\\Users\\\\v\\\\AppData\\\\Local\\\\Temp\\\\p.dll\"\n");
        var c = Assert.Single(f, x => x.RuleId == "cor-profiler");
        Assert.Equal(Severity.High, c.Severity);
    }

    [Fact]
    public void Detects_Winlogon_Tamper()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\n\"Shell\"=\"explorer.exe, c:\\\\evil.exe\"\n");
        Assert.Contains(f, x => x.RuleId == "winlogon-tamper");
    }

    [Fact]
    public void Legit_Winlogon_Shell_Not_Flagged()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\n\"Shell\"=\"explorer.exe\"\n");
        Assert.DoesNotContain(f, x => x.RuleId == "winlogon-tamper");
    }

    [Fact]
    public void Detects_Service_Imagepath_In_Userwritable()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\S]\n\"ImagePath\"=\"C:\\\\ProgramData\\\\p.exe\"\n");
        Assert.Contains(f, x => x.RuleId == "service-imagepath" && x.Technique == "T1543.003");
    }

    [Fact]
    public void Detects_Shell_Verb_Hijack()
    {
        var f = Scan("[HKEY_CURRENT_USER\\Software\\Classes\\myproto\\shell\\open\\command]\n@=\"mshta.exe http://x\"\n");
        Assert.Contains(f, x => x.RuleId == "shell-verb-hijack");
    }

    [Fact]
    public void Baseline_Suppresses_By_Fingerprint()
    {
        var reg = "[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{A}\\InprocServer32]\n@=\"c:\\\\windows\\\\x.dll\"\n";
        var f = Scan(reg);
        var fp = f.First(x => x.RuleId == "com-hijack").Fingerprint();
        var opts = new DetectorOptions();
        opts.Baseline.Add(fp);
        Assert.DoesNotContain(Scan(reg, opts), x => x.RuleId == "com-hijack");
    }

    [Fact]
    public void Fingerprint_Is_Stable_And_16_Hex_Chars()
    {
        var reg = "[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{A}\\InprocServer32]\n@=\"c:\\\\x.dll\"\n";
        var a = Scan(reg).First().Fingerprint();
        var b = Scan(reg).First().Fingerprint();
        Assert.Equal(a, b);
        Assert.Equal(16, a.Length);
        Assert.Matches("^[0-9a-f]{16}$", a);
    }

    [Fact]
    public void SelfTest_Sample_Produces_Nine_High_Findings()
    {
        var f = Detectors.Run(RegParser.Parse(Samples.SelfTest()));
        Assert.Equal(9, f.Count(x => x.Severity >= Severity.High));
    }

    [Fact]
    public void Clean_Export_Produces_No_Findings()
    {
        var f = Scan("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor\\App]\n\"Version\"=\"1.2.3\"\n");
        Assert.Empty(f);
    }
}
