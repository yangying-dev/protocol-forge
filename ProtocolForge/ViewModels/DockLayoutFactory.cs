using Dock.Avalonia.Controls;
using Dock.Model.Controls;
using Dock.Model.Core;
using Dock.Model.Mvvm;
using Dock.Model.Mvvm.Controls;
using ProtocolForge.Services;

namespace ProtocolForge.ViewModels;

/// <summary>
/// 默认停靠布局:上=数据包列表,下左=协议树,下右=十六进制编辑器,底部=统计(默认隐藏)。
/// <c>HideToolsOnClose</c> 使面板 X 按钮隐藏而非移除,视图菜单的勾选状态跟随 HiddenDockables。
/// </summary>
public sealed class DockLayoutFactory : Factory
{
    public const string PacketListId = "pane.packet-list";
    public const string ProtocolTreeId = "pane.protocol-tree";
    public const string HexEditorId = "pane.hex-editor";
    public const string StatisticsId = "pane.statistics";

    public const string RootId = "dock.root";
    public const string MainLayoutId = "dock.main";
    public const string TopDockId = "dock.packet-list";
    public const string BottomAreaId = "dock.tree-hex";
    public const string TreeDockId = "dock.protocol-tree";
    public const string HexDockId = "dock.hex-editor";
    public const string StatsDockId = "dock.statistics";

    public override IRootDock CreateLayout()
    {
        var packetList = new PacketListDock
        {
            Id = PacketListId,
            Title = LocalizationService.Resolve("Panel.PacketList"),
            Proportion = 0.4,
        };
        var protocolTree = new ProtocolTreeDock
        {
            Id = ProtocolTreeId,
            Title = LocalizationService.Resolve("Panel.ProtocolTree"),
            Proportion = 0.5,
        };
        var hexEditor = new HexEditorDock
        {
            Id = HexEditorId,
            Title = LocalizationService.Resolve("Panel.HexEditor"),
            Proportion = 0.5,
        };
        var statistics = new StatisticsDock
        {
            Id = StatisticsId,
            Title = LocalizationService.Resolve("Panel.Statistics"),
            Proportion = 0.2,
        };

        var treeDock = new ToolDock
        {
            Id = TreeDockId,
            ActiveDockable = protocolTree,
            VisibleDockables = CreateList<IDockable>(protocolTree),
            Proportion = 0.5,
        };
        var hexDock = new ToolDock
        {
            Id = HexDockId,
            ActiveDockable = hexEditor,
            VisibleDockables = CreateList<IDockable>(hexEditor),
            Proportion = 0.5,
        };
        var bottomArea = new ProportionalDock
        {
            Id = BottomAreaId,
            Orientation = Orientation.Horizontal,
            VisibleDockables = CreateList<IDockable>(
                treeDock,
                new ProportionalDockSplitter { CanResize = true },
                hexDock),
            ActiveDockable = treeDock,
            Proportion = 0.4,
        };
        var topDock = new ToolDock
        {
            Id = TopDockId,
            ActiveDockable = packetList,
            VisibleDockables = CreateList<IDockable>(packetList),
            Proportion = 0.4,
        };
        var statsDock = new ToolDock
        {
            Id = StatsDockId,
            ActiveDockable = statistics,
            VisibleDockables = CreateList<IDockable>(statistics),
            Proportion = 0.2,
        };
        var mainLayout = new ProportionalDock
        {
            Id = MainLayoutId,
            Orientation = Orientation.Vertical,
            VisibleDockables = CreateList<IDockable>(
                topDock,
                new ProportionalDockSplitter { CanResize = true },
                bottomArea,
                new ProportionalDockSplitter { CanResize = true },
                statsDock),
            ActiveDockable = topDock,
        };

        var root = CreateRootDock();
        root.Id = RootId;
        root.IsCollapsable = false;
        root.VisibleDockables = CreateList<IDockable>(mainLayout);
        root.ActiveDockable = mainLayout;
        root.DefaultDockable = mainLayout;
        return root;
    }

    public override void InitLayout(IDockable layout)
    {
        HostWindowLocator = new Dictionary<string, Func<IHostWindow?>>
        {
            [nameof(IDockWindow)] = () => new HostWindow(),
        };
        HideToolsOnClose = true;
        base.InitLayout(layout);
        ApplyCompactToolChrome(layout);
    }

    // 四个面板标题栏统一改为悬停显示:平时收成 1px,悬停才展开,拖动/按钮全保留。
    // 放在 InitLayout 而非 CreateLayout:存档的 docklayout.json 不含 GripMode(反序列化
    // 回落 Visible=0),只有在这里对所有 ToolDock 归一,旧布局用户升级后才不会退回常显。
    private void ApplyCompactToolChrome(IDockable layout)
    {
        if (layout is not IDock dock)
            return;
        foreach (var toolDock in Find(dock, _ => true).OfType<IToolDock>())
            toolDock.GripMode = GripMode.AutoHide;
    }
}
