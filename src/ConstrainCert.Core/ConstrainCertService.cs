namespace ConstrainCert.Core;

public sealed class ConstrainCertService
{
    private readonly ConstrainedCertificateGenerator generator;
    private readonly ICertificateStoreService stores;
    private readonly AppStateStore stateStore;

    public ConstrainCertService(
        ConstrainedCertificateGenerator? generator = null,
        ICertificateStoreService? stores = null,
        AppStateStore? stateStore = null)
    {
        this.generator = generator ?? new ConstrainedCertificateGenerator();
        this.stores = stores ?? new CertificateStoreService();
        this.stateStore = stateStore ?? new AppStateStore();
    }

    public AppState? CurrentState() => stateStore.Load();

    public bool IsActive() => stateStore.Load() is { } state && stores.IsInstalled(state);

    public void Apply(IEnumerable<string> requestedDomains)
    {
        if (stores.IsOriginalRootTrusted())
        {
            throw new InvalidOperationException("Обнаружен оригинальный неограниченный root Минцифры. ConstrainCert не будет работать, пока он доверен Windows.");
        }

        using var bundle = generator.Generate(requestedDomains);
        var previous = stateStore.Load();
        stores.Install(bundle);
        var next = new AppState(CertificateConstants.StateVersion, bundle.Domains, bundle.AnchorSha256, bundle.CrossSha256, DateTimeOffset.UtcNow);

        try
        {
            if (previous is not null)
            {
                stores.RemoveOwned(previous);
            }

            stateStore.Save(next);
        }
        catch
        {
            stores.RemoveOwned(next);
            throw;
        }
    }

    public void RemoveAll()
    {
        var state = stateStore.Load();
        if (state is null)
        {
            return;
        }

        stores.RemoveOwned(state);
        stateStore.Delete();
    }
}
