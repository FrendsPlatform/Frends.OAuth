using System;
using System.Collections.Generic;

namespace Frends.OAuth.ParseToken.Definitions;

/// <summary>
/// Parse result.
/// </summary>
public class ParseResult
{
    /// <summary>
    /// Unique identifier of the security token.
    /// </summary>
    /// <example>9b3250d8d5ee432</example>
    public string Id { get; private set; }

    /// <summary>
    /// 'issuer' claim { iss, 'value' }.
    /// </summary>
    /// <example>https://frends.com/"</example>
    public string Issuer { get; private set; }

    /// <summary>
    /// 'audience' claim { aud, 'value' }.
    /// </summary>
    /// <example>"fIVLouKYRihXfYN6tdO9D3dwd6ZNS9Be"</example>
    public string Audiences { get; private set; }

    /// <summary>
    /// SecurityKeys for this instance.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SecurityKeyId { get; private set; }

    /// <summary>
    /// SecurityKeys for this instance.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SigningKeyId { get; private set; }

    /// <summary>
    /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a DateTime assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
    /// </summary>
    /// <example>0001-01-01 0:00:00</example>
    public DateTime ValidFrom { get; private set; }

    /// <summary>
    /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a DateTime assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
    /// </summary>
    /// <example>2018-10-18 20:00:00</example>
    public DateTime ValidTo { get; private set; }

    /// <summary>
    /// A dictionary of all claims in the token.
    /// </summary>
    /// <example>
    /// {
    ///     {"nickname", "foobar"},
    ///     {"name", "Foo Bar"},
    ///     {"updated_at", "2018-10-18T10:10:19.4430000Z"},
    ///     {"iss", "https://foo.bar/"},
    ///     ...
    /// }
    /// </example>
    public Dictionary<string, dynamic> Claims { get; private set; }

    internal ParseResult(string id, string issuer, string audiences, string securityKeyId, string signingKeyId, DateTime validFrom, DateTime validTo, Dictionary<string, dynamic> claims)
    {
        Id = id;
        Issuer = issuer;
        Audiences = audiences;
        SecurityKeyId = securityKeyId;
        SigningKeyId = signingKeyId;
        ValidFrom = validFrom;
        ValidTo = validTo;
        Claims = claims;
    }
}