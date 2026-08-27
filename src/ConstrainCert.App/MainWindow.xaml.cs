using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using ConstrainCert.Core;

namespace ConstrainCert.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<string> domains = [];
    private readonly ConstrainCertService service = new();

    public MainWindow()
    {
        InitializeComponent();
        DomainList.ItemsSource = domains;
        LoadState();
    }

    private void AddDomain_Click(object sender, RoutedEventArgs e)
    {
        TryAdd(DomainInput.Text);
        DomainInput.Clear();
    }

    private void AddTochkaPreset_Click(object sender, RoutedEventArgs e)
    {
        foreach (var domain in new[] { "tochka.com" })
        {
            TryAdd(domain);
        }
    }

    private void TryAdd(string input)
    {
        try
        {
            var domain = DomainPolicy.Normalize(input);
            if (!domains.Contains(domain, StringComparer.OrdinalIgnoreCase))
            {
                domains.Add(domain);
            }
        }
        catch (ArgumentException exception)
        {
            MessageBox.Show(this, exception.Message, "Не удалось добавить домен", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void DomainList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete && DomainList.SelectedItem is string selected)
        {
            domains.Remove(selected);
        }
    }

    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        if (DomainList.SelectedItem is string selected)
        {
            domains.Remove(selected);
        }
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            service.Apply(domains);
            StatusText.Text = "Защита установлена и проверена в хранилищах текущего пользователя.";
            MessageBox.Show(this, "Готово. Полностью закройте и снова откройте Chrome или Edge.", "ConstrainCert", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowError(exception);
        }
    }

    private void Verify_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StatusText.Text = service.IsActive()
                ? "Защита активна: anchor доверен, cross находится только среди промежуточных центров."
                : "Защита не активна или хранилище было изменено вне приложения.";
        }
        catch (Exception exception)
        {
            ShowError(exception);
        }
    }

    private void RemoveAll_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Удалить только сертификаты, созданные ConstrainCert?", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            service.RemoveAll();
            domains.Clear();
            StatusText.Text = "Сертификаты ConstrainCert удалены.";
        }
        catch (Exception exception)
        {
            ShowError(exception);
        }
    }

    private void LoadState()
    {
        var state = service.CurrentState();
        if (state is null)
        {
            return;
        }

        foreach (var domain in state.Domains)
        {
            domains.Add(domain);
        }

        StatusText.Text = service.IsActive() ? "Защита активна." : "Найдена предыдущая настройка, но она сейчас не активна.";
    }

    private void ShowError(Exception exception)
    {
        StatusText.Text = "Не удалось выполнить действие.";
        MessageBox.Show(this, exception.Message, "ConstrainCert", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
