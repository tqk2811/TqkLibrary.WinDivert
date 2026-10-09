using System.Collections.Concurrent;
using System.Net;
using TqkLibrary.WinDivert.Flow.Models;
using Xunit;

namespace TqkLibrary.WinDivert.Tests;

/// <summary>
/// <see cref="IpAddressKey"/> must be interchangeable with the <see cref="IPAddress"/> it replaces
/// on the hot path: same identity, same hash, and the same dictionary entry for a
/// <see cref="FlowKey"/> built either way.
/// </summary>
public class IpAddressKeyTests
{
    [Theory]
    [InlineData("192.168.1.20")]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    public void Ipv4_from_bytes_equals_from_IPAddress(string text)
    {
        IPAddress ip = IPAddress.Parse(text);
        IpAddressKey fromSpan = IpAddressKey.FromIPv4(ip.GetAddressBytes());
        IpAddressKey fromIp = IpAddressKey.FromIPAddress(ip);
        Assert.Equal(fromIp, fromSpan);
        Assert.Equal(fromIp.GetHashCode(), fromSpan.GetHashCode());
        Assert.True(fromIp == fromSpan);
        Assert.Equal(4, fromSpan.Family);
    }

    [Theory]
    [InlineData("2001:db8::20")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    public void Ipv6_from_bytes_equals_from_IPAddress(string text)
    {
        IPAddress ip = IPAddress.Parse(text);
        IpAddressKey fromSpan = IpAddressKey.FromIPv6(ip.GetAddressBytes());
        IpAddressKey fromIp = IpAddressKey.FromIPAddress(ip);
        Assert.Equal(fromIp, fromSpan);
        Assert.Equal(fromIp.GetHashCode(), fromSpan.GetHashCode());
        Assert.Equal(6, fromSpan.Family);
    }

    [Fact]
    public void Ipv4_is_not_its_ipv4_mapped_ipv6_form()
    {
        IpAddressKey v4 = IpAddressKey.FromIPAddress(IPAddress.Parse("1.2.3.4"));
        IpAddressKey mapped = IpAddressKey.FromIPAddress(IPAddress.Parse("::ffff:1.2.3.4"));
        Assert.NotEqual(v4, mapped);
        Assert.True(v4 != mapped);
    }

    [Fact]
    public void Any4_and_Any6_are_distinct_and_match_the_wildcards()
    {
        Assert.NotEqual(IpAddressKey.Any4, IpAddressKey.Any6);
        Assert.Equal(IpAddressKey.FromIPAddress(IPAddress.Any), IpAddressKey.Any4);
        Assert.Equal(IpAddressKey.FromIPAddress(IPAddress.IPv6Any), IpAddressKey.Any6);
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("2001:db8::dead:beef")]
    [InlineData("::ffff:1.2.3.4")]
    public void ToIPAddress_round_trips(string text)
    {
        IPAddress ip = IPAddress.Parse(text);
        IPAddress back = IpAddressKey.FromIPAddress(ip).ToIPAddress();
        Assert.Equal(ip, back);
        Assert.Equal(ip.AddressFamily, back.AddressFamily);
        Assert.Equal(ip.ToString(), IpAddressKey.FromIPAddress(ip).ToString());
    }

    [Fact]
    public void FlowKey_from_IPAddress_and_from_keys_hit_the_same_dictionary_entry()
    {
        IPAddress local = IPAddress.Parse("192.168.1.20");
        IPAddress remote = IPAddress.Parse("2001:db8::1");
        var fromObjects = new FlowKey(6, local, 50000, remote, 443);
        var fromKeys = new FlowKey(6, IpAddressKey.FromIPAddress(local), 50000, IpAddressKey.FromIPAddress(remote), 443);

        Assert.Equal(fromObjects, fromKeys);
        Assert.Equal(fromObjects.GetHashCode(), fromKeys.GetHashCode());

        var dict = new ConcurrentDictionary<FlowKey, int>();
        dict[fromObjects] = 1;
        Assert.True(dict.TryGetValue(fromKeys, out int value));
        Assert.Equal(1, value);
        Assert.Single(dict);
    }

    [Fact]
    public void FlowKey_returns_the_original_IPAddress_objects_when_built_from_them()
    {
        IPAddress local = IPAddress.Parse("192.168.1.20");
        IPAddress remote = IPAddress.Parse("93.184.216.34");
        var key = new FlowKey(17, local, 1, remote, 2);
        Assert.Same(local, key.LocalAddress);
        Assert.Same(remote, key.RemoteAddress);

        var fromKeys = new FlowKey(17, key.LocalKey, 1, key.RemoteKey, 2);
        Assert.Equal(local, fromKeys.LocalAddress);
        Assert.Equal(remote, fromKeys.RemoteAddress);
    }
}
