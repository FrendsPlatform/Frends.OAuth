namespace Frends.OAuth.CreateJWTToken.Definitions;

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
