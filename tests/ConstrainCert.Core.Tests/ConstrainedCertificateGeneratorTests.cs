using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ConstrainCert.Core;

namespace ConstrainCert.Core.Tests;

public sealed class ConstrainedCertificateGeneratorTests
{
    [Fact]
    public void LoadPinnedOriginalRoot_VerifiesExpectedFingerprint()
    {
        using var certificate = new ConstrainedCertificateGenerator().LoadPinnedOriginalRoot();
        Assert.Equal(CertificateConstants.OriginalRootSha256, Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));
    }

    [Fact]
    public void Generate_CreatesConstrainedCaCertificates()
    {
        using var bundle = new ConstrainedCertificateGenerator().Generate(["tochka.com", "example.test"]);
        using var source = new ConstrainedCertificateGenerator().LoadPinnedOriginalRoot();

        Assert.Equal(source.Subject, bundle.Cross.Subject);
        Assert.Equal(source.GetPublicKey(), bundle.Cross.GetPublicKey());
        Assert.Equal(CertificateConstants.AnchorCommonName, bundle.Anchor.GetNameInfo(X509NameType.SimpleName, false));
        Assert.True(GetExtension(bundle.Anchor, "2.5.29.30").Critical);
        Assert.True(GetExtension(bundle.Cross, "2.5.29.30").Critical);
        Assert.Contains("tochka.com", System.Text.Encoding.ASCII.GetString(GetExtension(bundle.Anchor, "2.5.29.30").RawData));
        Assert.Contains("example.test", System.Text.Encoding.ASCII.GetString(GetExtension(bundle.Cross, "2.5.29.30").RawData));
        Assert.True(GetExtension(bundle.Anchor, "2.5.29.30").RawData.AsSpan().IndexOf(new byte[] { 192, 0, 2, 0 }) >= 0);
        Assert.True(GetExtension(bundle.Cross, "2.5.29.30").RawData.AsSpan().IndexOf(new byte[] { 0x20, 0x01, 0x0d, 0xb8 }) >= 0);

        var anchorConstraints = Assert.IsType<X509BasicConstraintsExtension>(GetExtension(bundle.Anchor, "2.5.29.19"));
        var crossConstraints = Assert.IsType<X509BasicConstraintsExtension>(GetExtension(bundle.Cross, "2.5.29.19"));
        Assert.Equal(2, anchorConstraints.PathLengthConstraint);
        Assert.Equal(1, crossConstraints.PathLengthConstraint);

        var anchorUsage = Assert.IsType<X509KeyUsageExtension>(GetExtension(bundle.Anchor, "2.5.29.15"));
        Assert.Equal(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, anchorUsage.KeyUsages);
    }

    [Fact]
    public void Generate_RefusesEmptyDomainList()
    {
        Assert.Throws<ArgumentException>(() => new ConstrainedCertificateGenerator().Generate([]));
    }

    private static X509Extension GetExtension(X509Certificate2 certificate, string oid) =>
        certificate.Extensions.Cast<X509Extension>().Single(extension => extension.Oid?.Value == oid);
}
