using System;

namespace Frends.OAuth.ParseToken.Definitions;

/// <summary>
/// Token result.
/// </summary>
public class TokenResult
{
    /// <summary>
    /// Unique identifier of the security token.
    /// </summary>
    /// <example>9b3250d8d5ee432</example>
    public string Id { get; internal set; }

    /// <summary>
    /// 'issuer' claim { iss, 'value' }.
    /// </summary>
    /// <example>https://frends.com/"</example>
    public string Issuer { get; internal set; }

    /// <summary>
    /// 'audience' claim { aud, 'value' }.
    /// </summary>
    /// <example>"fIVLouKYRihXfYN6tdO9D3dwd6ZNS9Be"</example>
    public string Audiences { get; internal set; }

    /// <summary>
    /// SecurityKeys for this instance.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SecurityKeyId { get; internal set; }

    /// <summary>
    /// SecurityKeys for this instance.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SigningKeyId { get; internal set; }

    /// <summary>
    /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a DateTime assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
    /// </summary>
    /// <example>0001-01-01 0:00:00</example>
    public DateTime ValidFrom { get; internal set; }

    /// <summary>
    /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a DateTime assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
    /// </summary>
    /// <example>2018-10-18 20:00:00</example>
    public DateTime ValidTo { get; internal set; }
}