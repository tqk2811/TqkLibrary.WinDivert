using Xunit;
using static TqkLibrary.WinDivert.Pipeline.Helpers.PumpCoreHints;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// Core ranking for the pump threads' ideal processors, from synthetic CPU set topologies.
/// </summary>
public class PumpCoreHintsTests
{
    private static (int Group, int Cpu)[] Rank(params CpuSetEntry[] sets)
        => RankCores(sets).Select(c => ((int)c.Group, (int)c.Number)).ToArray();

    [Fact]
    public void IntelHybridWithHyperThreadingRanksPrimaryPCoresFirstAndCoreZeroLastAmongThem()
    {
        // 3 P-cores (2 logical processors each, class 1), then 2 E-cores (1 each, class 0).
        var sets = new List<CpuSetEntry>();
        byte lp = 0;
        for (byte core = 0; core < 3; core++)
        {
            sets.Add(new CpuSetEntry(0, lp++, core, 1));
            sets.Add(new CpuSetEntry(0, lp++, core, 1));
        }
        for (byte core = 3; core < 5; core++) sets.Add(new CpuSetEntry(0, lp++, core, 0));

        // P-cores 1 (LP 2) and 2 (LP 4), then core 0 (LP 0); then the E-cores (LP 6, 7).
        Assert.Equal(new[] { (0, 2), (0, 4), (0, 0), (0, 6), (0, 7) }, Rank(sets.ToArray()));
    }

    [Fact]
    public void AmdWithSmtTakesOneLogicalProcessorPerCoreAndCoreZeroLast()
    {
        var sets = new List<CpuSetEntry>();
        for (byte core = 0; core < 4; core++)
        {
            sets.Add(new CpuSetEntry(0, (byte)(core * 2), core, 0));
            sets.Add(new CpuSetEntry(0, (byte)(core * 2 + 1), core, 0));
        }

        Assert.Equal(new[] { (0, 2), (0, 4), (0, 6), (0, 0) }, Rank(sets.ToArray()));
    }

    [Fact]
    public void WithHyperThreadingOffEveryLogicalProcessorIsItsOwnCore()
    {
        var sets = Enumerable.Range(0, 4).Select(i => new CpuSetEntry(0, (byte)i, (byte)i, 0)).ToArray();

        Assert.Equal(new[] { (0, 1), (0, 2), (0, 3), (0, 0) }, Rank(sets));
    }

    [Fact]
    public void TheLowestLogicalIndexIsThePrimaryEvenWhenListedSecond()
    {
        var sets = new[]
        {
            new CpuSetEntry(0, 5, 2, 0),
            new CpuSetEntry(0, 4, 2, 0),
        };

        Assert.Equal(new[] { (0, 4) }, Rank(sets));
    }

    [Fact]
    public void MultipleGroupsOrderByGroupAndOnlyGroupZeroCoreZeroIsDemoted()
    {
        var sets = new[]
        {
            new CpuSetEntry(1, 0, 0, 0),  // group 1's core 0 is not the machine's core 0
            new CpuSetEntry(1, 1, 1, 0),
            new CpuSetEntry(0, 0, 0, 0),
            new CpuSetEntry(0, 1, 1, 0),
        };

        Assert.Equal(new[] { (0, 1), (1, 0), (1, 1), (0, 0) }, Rank(sets));
    }
}
