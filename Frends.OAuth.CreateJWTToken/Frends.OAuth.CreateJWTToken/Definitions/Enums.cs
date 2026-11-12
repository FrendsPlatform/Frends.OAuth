namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Algorithms for signing. HS* are symmetric algorithms, RS* and ES* asymmetric.
/// </summary>
public enum SigningAlgorithm
{
#pragma warning disable CS1591 // self explanatory
    /// <summary>RSA with SHA-256.</summary>
    RS256,
    /// <summary>RSA with SHA-384.</summary>
    RS384,
    /// <summary>RSA with SHA-512.</summary>
    RS512,
    /// <summary>HMAC with SHA-256.</summary>
    HS256,
    /// <summary>HMAC with SHA-384.</summary>
    HS384,
    /// <summary>HMAC with SHA-512.</summary>
    HS512,
    /// <summary>ECDSA with SHA-256.</summary>
    ES256,
    /// <summary>ECDSA with SHA-384.</summary>
    ES384,
    /// <summary>ECDSA with SHA-512.</summary>
    ES512,
#pragma warning restore CS1591 // self explanatory
}