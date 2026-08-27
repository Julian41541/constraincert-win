using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ConstrainCert.Core;

public sealed class ConstrainedCertificateGenerator
{
    public CertificateBundle Generate(IEnumerable<string> requestedDomains)
    {
        var domains = DomainPolicy.NormalizeMany(requestedDomains);
        if (domains.Count == 0)
        {
            throw new ArgumentException("Добавьте хотя бы один домен.", nameof(requestedDomains));
        }

        using var source = LoadPinnedOriginalRoot();
        using var anchorKey = RSA.Create(4096);
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddDays(-1);
        var notAfter = new DateTimeOffset(source.NotAfter.ToUniversalTime()).AddTicks(-1);
        var tenYears = now.AddYears(10);
        if (notAfter > tenYears)
        {
            notAfter = tenYears;
        }

        var anchorRequest = new CertificateRequest(
            $"CN={CertificateConstants.AnchorCommonName}, O=Personal local trust",
            anchorKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        AddCaExtensions(anchorRequest, anchorRequest.PublicKey, pathLength: 2);
        anchorRequest.CertificateExtensions.Add(NameConstraintsExtension.Create(domains));

        using var anchorWithKey = anchorRequest.CreateSelfSigned(notBefore, notAfter);
        var anchor = new X509Certificate2(anchorWithKey.Export(X509ContentType.Cert));

        var crossRequest = new CertificateRequest(source.SubjectName, source.PublicKey, HashAlgorithmName.SHA256);
        AddCaExtensions(crossRequest, source.PublicKey, pathLength: 1);
        crossRequest.CertificateExtensions.Add(NameConstraintsExtension.Create(domains));
        var generator = X509SignatureGenerator.CreateForRSA(anchorKey, RSASignaturePadding.Pkcs1);
        var cross = crossRequest.Create(anchor.SubjectName, generator, notBefore, notAfter, source.SerialNumberBytes.ToArray());

        return new CertificateBundle(anchor, cross, domains);
    }

    public X509Certificate2 LoadPinnedOriginalRoot()
    {
        const string resourceName = "ConstrainCert.Core.Resources.MinDigitalRoot.der.base64";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("Не найден встроенный root-сертификат Минцифры.");
        using var reader = new StreamReader(stream);
        var der = Convert.FromBase64String(reader.ReadToEnd());
        var certificate = new X509Certificate2(der);
        var actual = Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
        if (!string.Equals(actual, CertificateConstants.OriginalRootSha256, StringComparison.Ordinal))
        {
            certificate.Dispose();
            throw new CryptographicException("Встроенный root-сертификат не совпал с закреплённым SHA-256.");
        }

        return certificate;
    }

    private static void AddCaExtensions(CertificateRequest request, PublicKey publicKey, int pathLength)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: pathLength, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, critical: false));
    }
}
