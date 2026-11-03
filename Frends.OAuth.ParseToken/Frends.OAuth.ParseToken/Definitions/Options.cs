using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.OAuth.ParseToken.Definitions;

/// <summary>
/// Options.
/// </summary>
public class Options
{
    /// <summary>
    /// Should the issuer (iss) validation be skipped.
    /// </summary>
    /// <example>True</example>
    public bool SkipIssuerValidation { get; set; }

    /// <summary>
    /// Should audience (aud) validation be skipped.
    /// </summary>
    /// <example>True</example>
    public bool SkipAudienceValidation { get; set; }

    /// <summary>
    /// Should lifetime (exp,nbf) validation be skipped.
    /// </summary>
    /// <example>True</example>
    public bool SkipLifetimeValidation { get; set; }

    /// <summary>
    /// Clock skew tolerance in seconds applied to lifetime (exp,nbf) validation. Use 0 for no tolerance.
    /// </summary>
    /// <example>300</example>
    [DefaultValue(300)]
    [UIHint(nameof(SkipLifetimeValidation), "", false)]
    public int ClockSkewSeconds { get; set; } = 300;

    /// <summary>
    /// Should the Token be decrypted.
    /// </summary>
    /// <example>True</example>
    public bool DecryptToken { get; set; }

    /// <summary>
    /// Decryption key, should be in PEM format.
    /// </summary>
    /// <example>-----BEGIN RSA PRIVATE KEY-----TheKey-----END RSA PRIVATE KEY-----</example>
    [UIHint(nameof(DecryptToken), "", true)]
    [PasswordPropertyText]
    public string DecryptionKey { get; set; }
}