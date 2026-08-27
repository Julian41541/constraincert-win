using System.Security.Cryptography.X509Certificates;

namespace ConstrainCert.Core;

public sealed record CertificateBundle(
    X509Certificate2 Anchor,
    X509Certificate2 Cross,
    IReadOnlyList<string> Domains) : IDisposable
{
    public string AnchorSha256 => Convert.ToHexString(Anchor.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));
    public string CrossSha256 => Convert.ToHexString(Cross.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));

    public void Dispose()
    {
        Anchor.Dispose();
        Cross.Dispose();
    }
}
