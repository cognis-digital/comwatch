// comwatch — data model
// Part of the Cognis Neural Suite. Defensive triage only.
//
// Core types shared across the parser, detectors, and reporters.
namespace ComWatch;

/// <summary>Severity of a finding, ordered so higher = worse.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public static class SeverityExtensions
{
    public static string ToJsonString(this Severity s) => s switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "INFO",
    };

    /// <summary>SARIF result level mapping (error/warning/note).</summary>
    public static string ToSarifLevel(this Severity s) => s switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        Severity.Low => "note",
        _ => "none",
    };

    /// <summary>CEF numeric severity 0-10.</summary>
    public static int ToCefSeverity(this Severity s) => s switch
    {
        Severity.Critical => 10,
        Severity.High => 8,
        Severity.Medium => 5,
        Severity.Low => 3,
        _ => 1,
    };

    public static bool TryParse(string? text, out Severity sev)
    {
        sev = Severity.Info;
        if (string.IsNullOrWhiteSpace(text)) return false;
        switch (text.Trim().ToUpperInvariant())
        {
            case "CRITICAL": sev = Severity.Critical; return true;
            case "HIGH": sev = Severity.High; return true;
            case "MEDIUM": case "MED": sev = Severity.Medium; return true;
            case "LOW": sev = Severity.Low; return true;
            case "INFO": case "INFORMATIONAL": sev = Severity.Info; return true;
            default: return false;
        }
    }
}

/// <summary>A single registry key/value observation the parser produces.</summary>
public sealed record RegEntry(
    string Key,        // full key path, e.g. HKEY_CURRENT_USER\Software\Classes\CLSID\{..}\InprocServer32
    string Hive,       // HKCU / HKLM / HKU / HKCR / ?
    string? ValueName, // null for the (Default) value
    string ValueData,  // decoded value data (backslashes unescaped)
    int Line);         // 1-based source line number

/// <summary>A detection produced by a detector rule.</summary>
public sealed record Finding
{
    public required Severity Severity { get; init; }
    public required string RuleId { get; init; }       // stable rule id, e.g. "com-hijack"
    public required string Title { get; init; }         // short human title
    public required string Message { get; init; }       // full description
    public required string Technique { get; init; }     // MITRE ATT&CK technique id
    public string TechniqueName { get; init; } = "";
    public required string Hive { get; init; }
    public string? Clsid { get; init; }
    public required string Key { get; init; }
    public string? ValueName { get; init; }
    public required string Handler { get; init; }       // resolved handler / value data
    public int Line { get; init; }
    public string[] Tags { get; init; } = Array.Empty<string>();

    /// <summary>Stable fingerprint for de-duplication and baselining.</summary>
    public string Fingerprint()
    {
        var raw = $"{RuleId}|{Hive}|{Key}|{ValueName}|{Handler}";
        return Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(raw))).ToLowerInvariant()[..16];
    }
}
