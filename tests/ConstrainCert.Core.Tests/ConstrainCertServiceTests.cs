using ConstrainCert.Core;

namespace ConstrainCert.Core.Tests;

public sealed class ConstrainCertServiceTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "ConstrainCertTests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void Apply_ReplacesOnlyThePreviouslyManagedPair()
    {
        var stores = new FakeStoreService();
        var service = new ConstrainCertService(stores: stores, stateStore: new AppStateStore(directory));

        service.Apply(["tochka.com"]);
        service.Apply(["example.test"]);

        Assert.Equal(2, stores.InstallCount);
        Assert.Single(stores.Removed);
        Assert.True(service.IsActive());
    }

    [Fact]
    public void Apply_RefusesWhenOriginalRootIsTrusted()
    {
        var stores = new FakeStoreService { OriginalRootTrusted = true };
        var service = new ConstrainCertService(stores: stores, stateStore: new AppStateStore(directory));

        Assert.Throws<InvalidOperationException>(() => service.Apply(["tochka.com"]));
        Assert.Equal(0, stores.InstallCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class FakeStoreService : ICertificateStoreService
    {
        public bool OriginalRootTrusted { get; init; }
        public int InstallCount { get; private set; }
        public List<AppState> Removed { get; } = [];
        private AppState? active;

        public bool IsOriginalRootTrusted() => OriginalRootTrusted;

        public void Install(CertificateBundle bundle)
        {
            InstallCount++;
            active = new AppState(CertificateConstants.StateVersion, bundle.Domains, bundle.AnchorSha256, bundle.CrossSha256, DateTimeOffset.UtcNow);
        }

        public bool IsInstalled(AppState state) =>
            active is not null && active.AnchorSha256 == state.AnchorSha256 && active.CrossSha256 == state.CrossSha256;

        public void RemoveOwned(AppState state)
        {
            Removed.Add(state);
            if (active?.AnchorSha256 == state.AnchorSha256)
            {
                active = null;
            }
        }
    }
}
