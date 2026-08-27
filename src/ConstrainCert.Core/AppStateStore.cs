using System.Text.Json;

namespace ConstrainCert.Core;

public sealed class AppStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string statePath;

    public AppStateStore(string? localAppData = null)
    {
        var directory = Path.Combine(localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ConstrainCert");
        statePath = Path.Combine(directory, "state.json");
    }

    public AppState? Load()
    {
        if (!File.Exists(statePath))
        {
            return null;
        }

        var state = JsonSerializer.Deserialize<AppState>(File.ReadAllText(statePath), JsonOptions);
        return state is not null && state.Version == CertificateConstants.StateVersion ? state : null;
    }

    public void Save(AppState state)
    {
        var directory = Path.GetDirectoryName(statePath) ?? throw new InvalidOperationException("Не удалось определить каталог состояния.");
        Directory.CreateDirectory(directory);
        var temporary = statePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(state, JsonOptions));
        File.Move(temporary, statePath, overwrite: true);
    }

    public void Delete()
    {
        if (File.Exists(statePath))
        {
            File.Delete(statePath);
        }
    }
}
