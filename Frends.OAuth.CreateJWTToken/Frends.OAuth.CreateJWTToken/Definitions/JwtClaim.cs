using System.ComponentModel.DataAnnotations;

namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Class for describing of a single claim.
/// </summary>
public class JwtClaim
{
    /// <summary>
    /// Claim key.
    /// </summary>
    /// <example>Role</example>
    [DisplayFormat(DataFormatString = "Text")]
    public string ClaimKey { get; set; }

    /// <summary>
    /// Claim value.
    /// </summary>
    /// <example>Administrator</example>
    [DisplayFormat(DataFormatString = "Text")]
    public string ClaimValue { get; set; }
}
