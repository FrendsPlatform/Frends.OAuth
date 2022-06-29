using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Input parameters.
/// </summary>
public class Input
{
    /// <summary>
    /// Value for "iss" (Issuer) Claim.
    /// </summary>
    /// <example>Issuer</example>
    [DisplayFormat(DataFormatString = "Text")]
    [DefaultValue("Issuer")]
    public string Issuer { get; set; }

    /// <summary>
    /// Value for "aud" (Audience) Claim.
    /// </summary>
    /// <example>Audience</example>
    [DisplayFormat(DataFormatString = "Text")]
    [DefaultValue("Audience")]
    public string Audience { get; set; }

    /// <summary>
    /// Value for "exp" (Expiration Time) Claim.
    /// </summary>
    /// <example>DateTime.Now.AddDays(7)</example>
    [DefaultValue("DateTime.Now.AddDays(7)")]
    public DateTime? Expires { get; set; }

    /// <summary>
    /// Value for "nbf" (Not Before) Claim.
    /// </summary>
    /// <example>DateTime.Now.AddDays(1)</example>
    [DefaultValue("DateTime.Now.AddDays(1)")]
    public DateTime? NotBefore { get; set; }

    /// <summary>
    /// Value for "x5t" (X.509 Certificate SHA-1 Thumbprint) Header.
    /// </summary>
    /// <example>X5T</example>
    [DisplayFormat(DataFormatString = "Text")]
    [DefaultValue("X5T")]
    public string X509Thumbprint { get; set; }

    /// <summary>
    /// Private key for signing. The key should be in PEM format for asymmetric algorithms. If symmetric algorithms is used, key can be any string.
    /// </summary>
    /// <example>-----BEGIN RSA PRIVATE KEY-----TheKey-----END RSA PRIVATE KEY-----</example>
    [PasswordPropertyText]
    public string PrivateKey { get; set; }

    /// <summary>
    /// Algorithm used for signing, default is RS256. HS256/HS384/HS512 are symmetric algorithms, RS256/RS384/RS512 asymmetric.
    /// </summary>
    /// <example>RS256</example>
    [DefaultValue(SigningAlgorithm.RS256)]
    public SigningAlgorithm SigningAlgorithm { get; set; }

    /// <summary>
    /// Optional value(s) for "sub" (Subject) Claim. Multiple claims with same keys/names can be added.
    /// </summary>
    /// <example>Name, Value</example>
    public JwtClaim[] Claims { get; set; }
}

/// <summary>
/// Class for describing of a single claim.
/// </summary>
public class JwtClaim
{
    /// <summary>
    /// Claim key.
    /// </summary>
    /// <example>Name</example>
    public string ClaimKey { get; set; }

    /// <summary>
    /// Claim value.
    /// </summary>
    /// <example>Value</example>
    public string ClaimValue { get; set; }
}