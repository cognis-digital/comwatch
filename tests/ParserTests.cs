// comwatch — parser unit tests
using ComWatch;
using Xunit;

namespace ComWatch.Tests;

public class ParserTests
{
    [Fact]
    public void Parses_Default_And_Named_String_Values()
    {
        var text = "Windows Registry Editor Version 5.00\n\n" +
                   "[HKEY_CURRENT_USER\\Software\\Test]\n" +
                   "@=\"default-data\"\n" +
                   "\"Name\"=\"named-data\"\n";
        var entries = RegParser.Parse(text);
        Assert.Equal(2, entries.Count);
        Assert.Null(entries[0].ValueName);
        Assert.Equal("default-data", entries[0].ValueData);
        Assert.Equal("Name", entries[1].ValueName);
        Assert.Equal("named-data", entries[1].ValueData);
        Assert.Equal("HKCU", entries[0].Hive);
    }

    [Fact]
    public void Unescapes_Backslashes_And_Quotes()
    {
        var text = "[HKEY_LOCAL_MACHINE\\X]\n@=\"C:\\\\Windows\\\\System32\\\\a.dll\"\n";
        var entries = RegParser.Parse(text);
        Assert.Equal(@"C:\Windows\System32\a.dll", entries[0].ValueData);
    }

    [Fact]
    public void Skips_Comments_Blank_Lines_And_Banner()
    {
        var text = "REGEDIT4\n; a comment\n\n[HKEY_USERS\\S]\n\"k\"=\"v\"\n";
        var entries = RegParser.Parse(text);
        Assert.Single(entries);
        Assert.Equal("HKU", entries[0].Hive);
    }

    [Fact]
    public void Skips_Key_Deletion_Directives()
    {
        var text = "[-HKEY_CURRENT_USER\\Software\\Gone]\n[HKEY_CURRENT_USER\\Software\\Kept]\n\"k\"=\"v\"\n";
        var entries = RegParser.Parse(text);
        Assert.Single(entries);
        Assert.Contains("Kept", entries[0].Key);
    }

    [Fact]
    public void Decodes_Hex2_RegExpandSz_Utf16le()
    {
        // "cmd" as UTF-16LE hex: 63,00,6d,00,64,00,00,00
        var text = "[HKEY_LOCAL_MACHINE\\X]\n\"Path\"=hex(2):63,00,6d,00,64,00,00,00\n";
        var entries = RegParser.Parse(text);
        Assert.Equal("cmd", entries[0].ValueData);
    }

    [Fact]
    public void Reassembles_Backslash_Continued_Lines()
    {
        var text = "[HKEY_LOCAL_MACHINE\\X]\n\"B\"=hex(2):63,00,\\\n  6d,00,64,00,00,00\n";
        var entries = RegParser.Parse(text);
        Assert.Equal("cmd", entries[0].ValueData);
    }

    [Fact]
    public void Classifies_All_Hives()
    {
        var text = "[HKEY_CLASSES_ROOT\\a]\n\"k\"=\"v\"\n[HKEY_CURRENT_CONFIG\\b]\n\"k\"=\"v\"\n";
        var entries = RegParser.Parse(text);
        Assert.Equal("HKCR", entries[0].Hive);
        Assert.Equal("HKCC", entries[1].Hive);
    }

    [Fact]
    public void Empty_Input_Yields_No_Entries()
    {
        Assert.Empty(RegParser.Parse(""));
        Assert.Empty(RegParser.Parse("Windows Registry Editor Version 5.00\n"));
    }
}
