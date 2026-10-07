using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProtocolForge.Services;

/// <summary>
/// Information about a network adapter available for packet injection.
/// </summary>
public sealed record NetworkInterfaceInfo(
    string Id,
    string Name,
    string Description,
    IPAddress? IPv4Address,
    IPAddress? IPv6Address,
    string? MacAddress,
    bool IsLoopback,
    bool IsUp)
{
    public string DisplayName => IsLoopback
        ? $"↻ {Name} (Loopback)"
        : $"⇄ {Name} ({IPv4Address}){FormatMac(MacAddress)}";

    private static string FormatMac(string? mac)
        => string.IsNullOrEmpty(mac) ? string.Empty : $" · {mac}";
}

/// <summary>
/// Scans and enumerates available network interfaces on the local machine.
/// Cross-platform: works on Windows, Linux, and macOS.
/// </summary>
public sealed class NetworkInterfaceService
{
    /// <summary>
    /// Returns all non-virtual network interfaces with an IPv4 address.
    /// Sorted by name, loopback interfaces at the end.
    /// </summary>
    public ObservableCollection<NetworkInterfaceInfo> GetInterfaces()
    {
        var result = new ObservableCollection<NetworkInterfaceInfo>();

        try
        {
            var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .Select(ni =>
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses
                        .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                        ?.Address;
                    var ipv6 = ipProps.UnicastAddresses
                        .Where(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6
                                    && !u.Address.IsIPv6LinkLocal)
                        .Select(u => u.Address)
                        .FirstOrDefault()
                        ?? ipProps.UnicastAddresses
                            .Where(u => u.Address.AddressFamily == AddressFamily.InterNetworkV6)
                            .Select(u => u.Address)
                            .FirstOrDefault();

                    return new NetworkInterfaceInfo(
                        Id: ni.Id,
                        Name: ni.Name,
                        Description: ni.Description,
                        IPv4Address: ipv4,
                        IPv6Address: ipv6,
                        MacAddress: FormatMac(ni.GetPhysicalAddress().GetAddressBytes()),
                        IsLoopback: ni.NetworkInterfaceType == NetworkInterfaceType.Loopback,
                        IsUp: ni.OperationalStatus == OperationalStatus.Up
                    );
                })
                .Where(ni => ni.IPv4Address != null || ni.IsLoopback)
                .OrderBy(ni => ni.IsLoopback ? 1 : 0)
                .ThenBy(ni => ni.Name)
                .ToList();

            foreach (var info in interfaces)
                result.Add(info);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"NetworkInterface scan failed: {ex.Message}");
            // Return empty list — UI will show "No interfaces found"
        }

        return result;
    }

    private static string? FormatMac(byte[] mac)
    {
        if (mac == null || mac.Length < 6)
            return null;
        return string.Join(":", mac.Take(6).Select(b => b.ToString("X2")));
    }

    /// <summary>
    /// Returns the IP address for the selected interface, or null if unavailable.
    /// </summary>
    public IPAddress? GetInterfaceIP(string interfaceId)
    {
        try
        {
            var ni = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.Id == interfaceId && n.OperationalStatus == OperationalStatus.Up);

            if (ni == null) return null;

            return ni.GetIPProperties().UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                ?.Address;
        }
        catch
        {
            return null;
        }
    }
}
