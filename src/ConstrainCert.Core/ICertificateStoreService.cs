namespace ConstrainCert.Core;

public interface ICertificateStoreService
{
    bool IsOriginalRootTrusted();
    void Install(CertificateBundle bundle);
    bool IsInstalled(AppState state);
    void RemoveOwned(AppState state);
}
