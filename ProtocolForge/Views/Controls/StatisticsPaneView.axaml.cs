using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using ProtocolForge.ViewModels;

namespace ProtocolForge.Views.Controls;

public partial class StatisticsPaneView : UserControl
{
    private MainWindowViewModel? ViewModel => DataContext as MainWindowViewModel;

    public StatisticsPaneView()
    {
        InitializeComponent();
    }

    private async void OnStatisticsTapChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (ViewModel is not null && ViewModel.SelectedStatisticsTap is not null)
            await ViewModel.LoadStatisticsCommand.ExecuteAsync(null);
    }

    private async void OnRefreshStatisticsClick(object? sender, RoutedEventArgs e)
    {
        if (ViewModel is not null)
            await ViewModel.LoadStatisticsCommand.ExecuteAsync(null);
    }

    private async void OnCustomTapKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || ViewModel is null)
            return;
        e.Handled = true;
        await ViewModel.LoadStatisticsCommand.ExecuteAsync(null);
    }
}
