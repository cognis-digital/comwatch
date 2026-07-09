// comwatch — CLI entry point
// COM-hijack & persistence detector (C# / .NET). Part of the Cognis Neural Suite.
//
// Parses Windows registry exports (.reg) and flags persistence/hijack tradecraft
// without touching a live registry, so it runs on triage images, offline hives,
// any OS, and CI. Defensive triage only.
//
// Usage:
//   comwatch <path...>            analyze one or more .reg files (or directories)
//   comwatch -                    read a .reg export from stdin
//   comwatch --selftest           analyze the bundled sample export (demo/CI)
//   --format json|sarif|sigma|cef|table   output format (default: json)
//   --min-severity <level>        only report findings >= level (info..critical)
//   --include-info                include INFO baseline findings
//   --baseline <file>             suppress fingerprints listed in <file> (one per line)
//   --fail-on <level>             exit 2 when any finding >= level (default: high)
//   -q, --quiet                   suppress the human summary on stderr
//
// Structured report on stdout. Exit 2 if any finding at/above --fail-on, else 0.
using ComWatch;

static class Cli
{
    static int Main(string[] args)
    {
        string fmt = "json";
        var inputs = new List<string>();
        bool selftest = false, stdin = false, includeInfo = false, quiet = false;
        Severity minSev = Severity.Low; // hide INFO by default unless asked
        Severity failOn = Severity.High;
        string? baselineFile = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format" when i + 1 < args.Length: fmt = args[++i]; break;
                case "--min-severity" when i + 1 < args.Length:
                    if (!SeverityExtensions.TryParse(args[++i], out minSev))
                    { Console.Error.WriteLine($"comwatch: bad --min-severity '{args[i]}'"); return 1; }
                    break;
                case "--fail-on" when i + 1 < args.Length:
                    if (!SeverityExtensions.TryParse(args[++i], out failOn))
                    { Console.Error.WriteLine($"comwatch: bad --fail-on '{args[i]}'"); return 1; }
                    break;
                case "--baseline" when i + 1 < args.Length: baselineFile = args[++i]; break;
                case "--include-info": includeInfo = true; minSev = Severity.Info; break;
                case "-q" or "--quiet": quiet = true; break;
                case "--selftest": selftest = true; break;
                case "--version": Console.WriteLine("comwatch 2.0.0"); return 0;
                case "-h" or "--help": PrintHelp(); return 0;
                case "-": stdin = true; break;
                default:
                    if (args[i].StartsWith("--"))
                    { Console.Error.WriteLine($"comwatch: unknown option '{args[i]}'"); return 1; }
                    inputs.Add(args[i]);
                    break;
            }
        }

        if (!selftest && !stdin && inputs.Count == 0)
        {
            Console.Error.WriteLine("comwatch: no input (.reg file/dir, '-' for stdin, or --selftest). See --help.");
            return 1;
        }

        var opts = new DetectorOptions { IncludeInfo = includeInfo };
        if (baselineFile != null)
        {
            try
            {
                foreach (var l in File.ReadAllLines(baselineFile))
                {
                    var t = l.Trim();
                    if (t.Length > 0 && !t.StartsWith("#")) opts.Baseline.Add(t);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"comwatch: cannot read baseline '{baselineFile}': {ex.Message}");
                return 1;
            }
        }

        // Collect (source-label, text) pairs.
        var sources = new List<(string label, string text)>();
        try
        {
            if (selftest) sources.Add(("<selftest>", Samples.SelfTest()));
            if (stdin) sources.Add(("<stdin>", Console.In.ReadToEnd()));
            foreach (var input in inputs)
            {
                if (Directory.Exists(input))
                {
                    var regs = Directory.EnumerateFiles(input, "*.reg", SearchOption.AllDirectories)
                                        .OrderBy(p => p, StringComparer.Ordinal).ToList();
                    if (regs.Count == 0)
                        Console.Error.WriteLine($"comwatch: no .reg files under directory '{input}'");
                    foreach (var f in regs) sources.Add((f, File.ReadAllText(f)));
                }
                else
                {
                    sources.Add((input, File.ReadAllText(input)));
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"comwatch: cannot read input: {ex.Message}");
            return 1;
        }

        // Analyze all sources; aggregate findings, keep a combined source label.
        var allFindings = new List<Finding>();
        foreach (var (_, text) in sources)
        {
            var entries = RegParser.Parse(text);
            allFindings.AddRange(Detectors.Run(entries, opts));
        }
        var filtered = allFindings.Where(f => f.Severity >= minSev)
                                  .OrderByDescending(f => f.Severity).ToList();
        string srcLabel = sources.Count == 1 ? sources[0].label : $"{sources.Count} source(s)";
        var result = new ScanResult(srcLabel, filtered);

        string output;
        try { output = Reporters.Render(result, fmt); }
        catch (ArgumentException ex) { Console.Error.WriteLine($"comwatch: {ex.Message}"); return 1; }
        Console.WriteLine(output);

        if (!quiet)
            Console.Error.WriteLine(
                $"comwatch: {result.Total} finding(s), {result.Findings.Count(f => f.Severity >= failOn)} at/above {failOn.ToJsonString()}.");

        return result.Findings.Any(f => f.Severity >= failOn) ? 2 : 0;
    }

    static void PrintHelp()
    {
        Console.WriteLine(
@"comwatch 2.0.0 — COM-hijack & persistence detector (Cognis Digital)

USAGE:
  comwatch <path...>          analyze .reg file(s) or directories (recursive)
  comwatch -                  read a .reg export from stdin
  comwatch --selftest         analyze the bundled sample export

OPTIONS:
  --format <fmt>              json | sarif | sigma | cef | table   (default json)
  --min-severity <level>      report only findings >= level (info|low|medium|high|critical)
  --include-info              include INFO baseline findings
  --baseline <file>           suppress fingerprints listed in <file>
  --fail-on <level>           exit 2 when any finding >= level (default high)
  -q, --quiet                 suppress the human summary on stderr
  --version                   print version
  -h, --help                  this help

EXIT CODES:  0 = clean (below --fail-on)   2 = finding at/above --fail-on   1 = usage/IO error

Defensive triage only. Use on data you are authorized to examine.");
    }
}
