using ConstrainCert.Core;

namespace ConstrainCert.Core.Tests;

public sealed class AppStateStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "ConstrainCertTests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void SaveLoadDelete_RoundTripsOnlyNonSecretMetadata()
    {
        var store = new AppStateStore(directory);
        var state = new AppState(CertificateConstants.StateVersion, ["tochka.com"], "AA", "BB", DateTimeOffset.UtcNow);

        store.Save(state);

        var loaded = Assert.IsType<AppState>(store.Load());
        Assert.Equal(state.Version, loaded.Version);
        Assert.Equal(state.Domains, loaded.Domains);
        Assert.Equal(state.AnchorSha256, loaded.AnchorSha256);
        Assert.Equal(state.CrossSha256, loaded.CrossSha256);
        store.Delete();
        Assert.Null(store.Load());
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
