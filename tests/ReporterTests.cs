// comwatch — reporter unit tests
using System.Text.Json;
using ComWatch;
using Xunit;

namespace ComWatch.Tests;

public class ReporterTests
{
    static ScanResult SelfResult()
    {
        var f = Detectors.Run(RegParser.Parse(Samples.SelfTest()))
                         .OrderByDescending(x => x.Severity).ToList();
        return new ScanResult("<selftest>", f);
    }

    [Fact]
    public void Json_Is_Valid_And_Has_Findings_Array()
    {
        using var doc = JsonDocument.Parse(Reporters.Render(SelfResult(), "json"));
        var root = doc.RootElement;
        Assert.Equal("comwatch", root.GetProperty("tool").GetString());
        Assert.True(root.GetProperty("findings").GetArrayLength() >= 9);
        Assert.Equal(9, root.GetProperty("high_count").GetInt32());
    }

    [Fact]
    public void Sarif_Is_Valid_210_With_Rules_And_Results()
    {
        using var doc = JsonDocument.Parse(Reporters.Render(SelfResult(), "sarif"));
        var root = doc.RootElement;
        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        Assert.True(root.TryGetProperty("$schema", out _));
        var run = root.GetProperty("runs")[0];
        Assert.Equal("comwatch", run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString());
        Assert.True(run.GetProperty("results").GetArrayLength() >= 9);
        Assert.True(run.GetProperty("tool").GetProperty("driver").GetProperty("rules").GetArrayLength() >= 1);
    }

    [Fact]
    public void Sigma_Contains_Technique_Tag()
    {
        var s = Reporters.Render(SelfResult(), "sigma");
        Assert.Contains("attack.t1546.015", s);
        Assert.Contains("logsource:", s);
    }

    [Fact]
    public void Cef_Lines_Start_With_Cef_Header()
    {
        var lines = Reporters.Render(SelfResult(), "cef").Split('\n');
        Assert.All(lines, l => Assert.StartsWith("CEF:0|Cognis Digital|comwatch|", l));
    }

    [Fact]
    public void Table_Is_Human_Readable()
    {
        var t = Reporters.Render(SelfResult(), "table");
        Assert.Contains("comwatch", t);
        Assert.Contains("HIGH", t);
    }

    [Fact]
    public void Unknown_Format_Throws()
    {
        Assert.Throws<ArgumentException>(() => Reporters.Render(SelfResult(), "yaml"));
    }

    [Fact]
    public void ExitCode_Is_Two_When_High_Present_Else_Zero()
    {
        Assert.Equal(2, SelfResult().ExitCode);
        Assert.Equal(0, new ScanResult("x", new List<Finding>()).ExitCode);
    }
}
