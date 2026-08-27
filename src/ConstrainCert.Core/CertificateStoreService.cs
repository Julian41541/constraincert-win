using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ConstrainCert.Core;

public sealed class CertificateStoreService : ICertificateStoreService
{
    public bool IsOriginalRootTrusted()
    {
        return ContainsThumbprint(StoreName.Root, StoreLocation.CurrentUser, CertificateConstants.OriginalRootSha256) ||
               ContainsThumbprint(StoreName.Root, StoreLocation.LocalMachine, CertificateConstants.OriginalRootSha256);
    }

    public void Install(CertificateBundle bundle)
    {
        if (IsOriginalRootTrusted())
        {
            throw new InvalidOperationException("Обнаружен оригинальный неограниченный root Минцифры. Удалите его вручную из доверенных корневых центров, затем повторите попытку.");
        }

        using var root = Open(StoreName.Root, OpenFlags.ReadWrite);
        using var intermediate = Open(StoreName.CertificateAuthority, OpenFlags.ReadWrite);
        root.Add(bundle.Anchor);
        intermediate.Add(bundle.Cross);

        if (!ContainsThumbprint(StoreName.Root, StoreLocation.CurrentUser, bundle.AnchorSha256) ||
            !ContainsThumbprint(StoreName.CertificateAuthority, StoreLocation.CurrentUser, bundle.CrossSha256) ||
            ContainsThumbprint(StoreName.Root, StoreLocation.CurrentUser, bundle.CrossSha256))
        {
            RemoveByThumbprint(root, bundle.AnchorSha256);
            RemoveByThumbprint(intermediate, bundle.CrossSha256);
            throw new CryptographicException("Windows поместила сертификаты не в те хранилища. Установка отменена.");
        }
    }

    public bool IsInstalled(AppState state)
    {
        return !IsOriginalRootTrusted() &&
               ContainsThumbprint(StoreName.Root, StoreLocation.CurrentUser, state.AnchorSha256) &&
               ContainsThumbprint(StoreName.CertificateAuthority, StoreLocation.CurrentUser, state.CrossSha256) &&
               !ContainsThumbprint(StoreName.Root, StoreLocation.CurrentUser, state.CrossSha256);
    }

    public void RemoveOwned(AppState state)
    {
        using var root = Open(StoreName.Root, OpenFlags.ReadWrite);
        using var intermediate = Open(StoreName.CertificateAuthority, OpenFlags.ReadWrite);
        RemoveByThumbprint(root, state.AnchorSha256);
        RemoveByThumbprint(intermediate, state.CrossSha256);
    }

    private static X509Store Open(StoreName storeName, OpenFlags flags)
    {
        var store = new X509Store(storeName, StoreLocation.CurrentUser);
        store.Open(flags);
        return store;
    }

    private static bool ContainsThumbprint(StoreName storeName, StoreLocation location, string expectedSha256)
    {
        try
        {
            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return store.Certificates.Cast<X509Certificate2>().Any(certificate =>
                string.Equals(GetSha256(certificate), expectedSha256, StringComparison.OrdinalIgnoreCase));
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void RemoveByThumbprint(X509Store store, string expectedSha256)
    {
        foreach (var certificate in store.Certificates.Cast<X509Certificate2>().Where(certificate =>
                     string.Equals(GetSha256(certificate), expectedSha256, StringComparison.OrdinalIgnoreCase)).ToArray())
        {
            store.Remove(certificate);
            certificate.Dispose();
        }
    }

    private static string GetSha256(X509Certificate2 certificate) =>
        Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
}
