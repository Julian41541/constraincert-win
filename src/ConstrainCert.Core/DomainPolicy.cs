using System.Globalization;

namespace ConstrainCert.Core;

public static class DomainPolicy
{
    private static readonly HashSet<string> UnsafeZones = new(StringComparer.OrdinalIgnoreCase)
    {
        "ru", "su", "xn--p1ai",
    };

    public static string Normalize(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var domain = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (domain.StartsWith(".", StringComparison.Ordinal))
        {
            domain = domain[1..];
        }

        if (domain.Contains("://", StringComparison.Ordinal) ||
            domain.Contains('/') ||
            domain.Contains('@') ||
            System.Net.IPAddress.TryParse(domain, out _))
        {
            throw new ArgumentException("Введите доменное имя, а не URL или IP-адрес.", nameof(value));
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(domain);
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("Некорректное доменное имя.", nameof(value), exception);
        }

        if (UnsafeZones.Contains(ascii) || !ascii.Contains('.', StringComparison.Ordinal))
        {
            throw new ArgumentException("Нельзя добавлять широкую доменную зону. Укажите конкретный домен.", nameof(value));
        }

        return ascii;
    }

    public static IReadOnlyList<string> NormalizeMany(IEnumerable<string> domains) =>
        domains.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray();
}
