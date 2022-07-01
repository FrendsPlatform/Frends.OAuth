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