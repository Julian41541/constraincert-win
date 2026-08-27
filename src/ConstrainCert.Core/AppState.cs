namespace ConstrainCert.Core;

public sealed record AppState(
    string Version,
    IReadOnlyList<string> Domains,
    string AnchorSha256,
    string CrossSha256,
    DateTimeOffset AppliedAtUtc);
