namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Algorithms for signing. HS* are symmetric algorithms, RS* and ES* asymmetric.
/// </summary>
public enum SigningAlgorithm
{
#pragma warning disable CS1591 // self explanatory
    RS256,
    RS384,
    RS512,
    HS256,
    HS384,
    HS512,
    ES256,
    ES384,
    ES512
#pragma warning restore CS1591 // self explanatory
}