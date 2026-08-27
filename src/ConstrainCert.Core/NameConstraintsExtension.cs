using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace ConstrainCert.Core;

internal static class NameConstraintsExtension
{
    private const string Oid = "2.5.29.30";

    public static X509Extension Create(IReadOnlyList<string> domains)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        foreach (var domain in domains)
        {
            WriteGeneralSubtree(writer, 2, domain);
            WriteGeneralSubtree(writer, 2, $".{domain}");
        }

        WriteIpGeneralSubtree(writer, [192, 0, 2, 0, 255, 255, 255, 255]);
        WriteIpGeneralSubtree(writer, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]);
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));

        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
        WriteGeneralSubtree(writer, 1, ".");
        WriteGeneralSubtree(writer, 6, ".");
        writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));

        writer.PopSequence();
        return new X509Extension(Oid, writer.Encode(), critical: true);
    }

    private static void WriteGeneralSubtree(AsnWriter writer, int tagValue, string value)
    {
        writer.PushSequence();
        writer.WriteCharacterString(UniversalTagNumber.IA5String, value, new Asn1Tag(TagClass.ContextSpecific, tagValue));
        writer.PopSequence();
    }

    private static void WriteIpGeneralSubtree(AsnWriter writer, byte[] value)
    {
        writer.PushSequence();
        writer.WriteOctetString(value, new Asn1Tag(TagClass.ContextSpecific, 7));
        writer.PopSequence();
    }
}
