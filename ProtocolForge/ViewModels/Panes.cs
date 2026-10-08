using System.Runtime.Serialization;
using Dock.Model.Mvvm.Controls;

namespace ProtocolForge.ViewModels;

/// <summary>
/// 停靠面板基类。Dock 的 JSON 序列化是多态的（$type 判别符），派生面板类型必须是
/// public 非抽象类才能被 DockSerializer 多态解析还原。
/// 宿主 ViewModel 引用标了 <see cref="IgnoreDataMemberAttribute"/> 不参与序列化，
/// 反序列化后由 <see cref="MainWindowViewModel"/> 重新挂回。
/// </summary>
public abstract class PaneDock : Tool
{
    /// <summary>宿主 ViewModel。面板视图的 DataContext 即取自此引用（见 App.axaml 的 DataTemplate）。</summary>
    [IgnoreDataMember]
    public MainWindowViewModel? Host { get; set; }

    /// <summary>
    /// 被隐藏时原宿主停靠的 Id。<c>OriginalOwner</c> 被 Dock 标了 IgnoreDataMember 不落盘，
    /// 重启后靠这个 Id 把 <see cref="Dock.Model.Core.IDockable.OriginalOwner"/> 接回去，
    /// 视图菜单的恢复（RestoreDockable）才能把面板放回原来的停靠而不是变成孤儿。
    /// </summary>
    public string? OriginalOwnerId { get; set; }
}

public sealed class PacketListDock : PaneDock { }

public sealed class ProtocolTreeDock : PaneDock { }

public sealed class HexEditorDock : PaneDock { }

public sealed class StatisticsDock : PaneDock { }
