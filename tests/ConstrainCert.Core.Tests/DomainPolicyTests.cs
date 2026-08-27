using ConstrainCert.Core;

namespace ConstrainCert.Core.Tests;

public sealed class DomainPolicyTests
{
    [Theory]
    [InlineData("tochka.com", "tochka.com")]
    [InlineData(" TOCHKA.COM. ", "tochka.com")]
    [InlineData(".tochka.com", "tochka.com")]
    [InlineData("пример.рф", "xn--e1afmkfd.xn--p1ai")]
    public void Normalize_ReturnsCanonicalAscii(string value, string expected)
    {
        Assert.Equal(expected, DomainPolicy.Normalize(value));
    }

    [Theory]
    [InlineData("https://tochka.com")]
    [InlineData("tochka.com/path")]
    [InlineData("192.0.2.1")]
    [InlineData("ru")]
    [InlineData("su")]
    [InlineData("xn--p1ai")]
    public void Normalize_RejectsUnsafeInputs(string value)
    {
        Assert.Throws<ArgumentException>(() => DomainPolicy.Normalize(value));
    }
}
