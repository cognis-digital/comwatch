// comwatch — Windows registry (.reg) export parser
// Part of the Cognis Neural Suite. Defensive triage only.
//
// Clean-room parser for the "Windows Registry Editor Version 5.00" text export
// format produced by `reg export` / RegEdit. No live registry access, so it
// runs on triage images, exported hives, and CI runners of any OS.
//
// Handles:
//   * [Key] section headers (and [-Key] deletions, which are skipped)
//   * @="..."           the (Default) string value
//   * "name"="..."      named string values (REG_SZ / REG_EXPAND_SZ text form)
//   * "name"=hex(2):..  REG_EXPAND_SZ encoded as UTF-16LE hex -> decoded text
//   * "name"=hex(7):..  REG_MULTI_SZ (decoded, NUL-joined with ';')
//   * "name"=dword:..   left as-is (numeric)
//   * backslash line continuations for long hex values
//   * ';' comment lines and blank lines
using System.Text;
using System.Text.RegularExpressions;

namespace ComWatch;

public static class RegParser
{
    static readonly Regex KeyHeader = new(@"^\[(?<neg>-)?(?<key>.+)\]\s*$", RegexOptions.Compiled);
    static readonly Regex DefaultStr = new("^@=\"(?<v>.*)\"\\s*$", RegexOptions.Compiled);
    static readonly Regex NamedStr = new("^\"(?<n>(?:[^\"\\\\]|\\\\.)*)\"=\"(?<v>.*)\"\\s*$", RegexOptions.Compiled);
    static readonly Regex NamedHex = new("^\"(?<n>(?:[^\"\\\\]|\\\\.)*)\"=(?<default>@)?hex(?:\\((?<t>[0-9a-fA-F]+)\\))?:(?<rest>.*)$", RegexOptions.Compiled);
    static readonly Regex DefaultHex = new(@"^@=hex(?:\((?<t>[0-9a-fA-F]+)\))?:(?<rest>.*)$", RegexOptions.Compiled);

    /// <summary>Parse registry export text into a flat list of entries.</summary>
    public static List<RegEntry> Parse(string text)
    {
        var entries = new List<RegEntry>();
        var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

        string curKey = "";
        string curHive = "?";
        int i = 0;
        while (i < lines.Length)
        {
            var raw = lines[i];
            var line = raw.Trim();
            int lineNo = i + 1;
            i++;

            if (line.Length == 0) continue;
            if (line.StartsWith(";")) continue;
            // Skip the format banner.
            if (line.StartsWith("Windows Registry Editor", StringComparison.OrdinalIgnoreCase)) continue;
            if (line.StartsWith("REGEDIT4", StringComparison.OrdinalIgnoreCase)) continue;

            var hm = KeyHeader.Match(line);
            if (hm.Success)
            {
                // [-Key] is a deletion directive; there is nothing to analyze.
                if (hm.Groups["neg"].Success) { curKey = ""; continue; }
                curKey = hm.Groups["key"].Value.Trim();
                curHive = ClassifyHive(curKey);
                continue;
            }

            if (curKey.Length == 0) continue;

            // Reassemble backslash-continued value lines (common for long hex).
            while (line.EndsWith("\\") && i < lines.Length)
            {
                line = line[..^1] + lines[i].Trim();
                i++;
            }

            // (Default) string value.
            var dm = DefaultStr.Match(line);
            if (dm.Success)
            {
                entries.Add(new RegEntry(curKey, curHive, null, Unescape(dm.Groups["v"].Value), lineNo));
                continue;
            }

            // Named string value.
            var nm = NamedStr.Match(line);
            if (nm.Success)
            {
                entries.Add(new RegEntry(curKey, curHive, Unescape(nm.Groups["n"].Value),
                    Unescape(nm.Groups["v"].Value), lineNo));
                continue;
            }

            // (Default) hex value.
            var dh = DefaultHex.Match(line);
            if (dh.Success)
            {
                var decoded = DecodeHex(dh.Groups["t"].Success ? dh.Groups["t"].Value : "1", dh.Groups["rest"].Value);
                entries.Add(new RegEntry(curKey, curHive, null, decoded, lineNo));
                continue;
            }

            // Named hex value (REG_EXPAND_SZ / REG_MULTI_SZ / REG_BINARY).
            var nh = NamedHex.Match(line);
            if (nh.Success)
            {
                var decoded = DecodeHex(nh.Groups["t"].Success ? nh.Groups["t"].Value : "3", nh.Groups["rest"].Value);
                entries.Add(new RegEntry(curKey, curHive, Unescape(nh.Groups["n"].Value), decoded, lineNo));
                continue;
            }

            // dword: / other typed lines — capture the raw right-hand side as data.
            int eq = line.IndexOf('=');
            if (eq > 0)
            {
                var namePart = line[..eq].Trim();
                var dataPart = line[(eq + 1)..].Trim();
                string? name = namePart == "@" ? null : namePart.Trim('"');
                entries.Add(new RegEntry(curKey, curHive, name, dataPart, lineNo));
            }
        }

        return entries;
    }

    static string ClassifyHive(string key)
    {
        if (key.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)) return "HKCU";
        if (key.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)) return "HKLM";
        if (key.StartsWith("HKEY_USERS", StringComparison.OrdinalIgnoreCase)) return "HKU";
        if (key.StartsWith("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase)) return "HKCR";
        if (key.StartsWith("HKEY_CURRENT_CONFIG", StringComparison.OrdinalIgnoreCase)) return "HKCC";
        return "?";
    }

    /// <summary>Unescape .reg string escaping: \\ -> \, \" -> ".</summary>
    static string Unescape(string s) => s.Replace("\\\\", "\\").Replace("\\\"", "\"");

    /// <summary>
    /// Decode a comma-separated hex byte list. type 2 = REG_EXPAND_SZ (UTF-16LE),
    /// type 1 = REG_SZ (UTF-16LE), type 7 = REG_MULTI_SZ (UTF-16LE, NUL-separated).
    /// Anything else is rendered as a compact hex string.
    /// </summary>
    static string DecodeHex(string typeHex, string rest)
    {
        int type;
        try { type = Convert.ToInt32(typeHex, 16); } catch { type = 3; }

        var bytes = ParseHexBytes(rest);
        if (bytes.Length == 0) return "";

        if (type is 1 or 2 or 7)
        {
            // UTF-16LE text (drop trailing NULs). MULTI_SZ joins fields with ';'.
            var text = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
            if (type == 7) text = text.Replace('\0', ';').Trim(';');
            return text;
        }
        // REG_BINARY / dword etc: hex string.
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    static byte[] ParseHexBytes(string rest)
    {
        var parts = rest.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var buf = new List<byte>(parts.Length);
        foreach (var p in parts)
        {
            if (p.Length == 0) continue;
            if (byte.TryParse(p, System.Globalization.NumberStyles.HexNumber, null, out var b))
                buf.Add(b);
        }
        return buf.ToArray();
    }
}
