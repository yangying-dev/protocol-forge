namespace ProtocolForge.Services;

/// <summary>
/// A probe-opened native L2 injection path (Npcap on Windows, BPF on macOS)
/// that can deliver complete Ethernet frames.
/// </summary>
internal interface IL2SendRung : IDisposable
{
    /// <summary>Underlying native device this rung sends on.</summary>
    string DeviceName { get; }

    /// <summary>
    /// Sends one frame. A null result means this rung cannot deliver the
    /// packet — the caller descends to the next ladder rung as usual.
    /// </summary>
    (PacketSendResult? Result, string? Error) TrySend(byte[] frame, int index, string interfaceName);
}