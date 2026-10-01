using CommunityToolkit.Mvvm.ComponentModel;

namespace ProtocolForge.Models;

public partial class HexByte : ObservableObject
{
    public int Offset { get; init; }

    [ObservableProperty]
    private byte _value;

    [ObservableProperty]
    private bool _isSelected;

    [ObservableProperty]
    private bool _isHighlighted;

    [ObservableProperty]
    private string _highlightColor = "Transparent";

    [ObservableProperty]
    private bool _isEdited;

    /// <summary>
    /// True while this byte belongs to an in-progress (uncommitted) hex edit run.
    /// Pending bytes read their display text from <see cref="PendingHexText"/> instead
    /// of <see cref="Value"/>; <see cref="Value"/> itself stays unchanged until commit.
    /// </summary>
    [ObservableProperty]
    private bool _isEditPending;

    /// <summary>
    /// The hex digits typed so far for this pending byte (1 or 2 characters).
    /// Empty when the byte has not been touched by the current run.
    /// </summary>
    [ObservableProperty]
    private string _pendingHexText = string.Empty;

    /// <summary>
    /// The ASCII character of the pending byte once its two digits are complete,
    /// otherwise the placeholder '?' while only the first digit has been typed.
    /// </summary>
    [ObservableProperty]
    private string _pendingAsciiText = string.Empty;

    public ProtocolField? AssociatedField { get; set; }

    /// <summary>
    /// Enters the pending (in-progress edit) state with the given display text.
    /// </summary>
    public void SetPending(string hexText, string asciiText)
    {
        IsEditPending = true;
        PendingHexText = hexText;
        PendingAsciiText = asciiText;
    }

    /// <summary>
    /// Leaves the pending state and restores the normal <see cref="HexValue"/> display.
    /// </summary>
    public void ClearPending()
    {
        IsEditPending = false;
        PendingHexText = string.Empty;
        PendingAsciiText = string.Empty;
    }

    public string HexValue => Value.ToString("X2");

    public string AsciiValue => Value >= 32 && Value <= 126
        ? ((char)Value).ToString()
        : ".";

    partial void OnValueChanged(byte value)
    {
        OnPropertyChanged(nameof(HexValue));
        OnPropertyChanged(nameof(AsciiValue));
    }
}
