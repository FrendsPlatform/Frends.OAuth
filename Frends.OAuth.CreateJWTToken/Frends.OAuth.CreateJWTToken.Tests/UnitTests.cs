using Frends.OAuth.CreateJWTToken.Definitions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Frends.OAuth.CreateJWTToken.Tests;

[TestClass]
public class UnitTests
{
    private static readonly string privateKey = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Keys/PK.pem")); //PK from community task
    private static readonly string x5t = "m5836ev678LlLGyFEdq+Ec71Inw="; //x5t from community task

    Input? input;

    /// <summary>
    /// Symmetric test.
    /// </summary>
    [TestMethod]
    public void CreateJwtTokenTestSymmetric()
    {
        input = new Input
        {
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = "AnySecretTextIsOKHere",
            SigningAlgorithm = SigningAlgorithm.HS256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } }
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsTrue(result.Token != null);

        // JWT tokens always have 2 dot separators between parts.
        Assert.IsTrue(result.Token.Count(i => i.Equals('.')) == 2);
    }

    /// <summary>
    /// Create without X509Thumbprint -> Symmetric.
    /// </summary>
    [TestMethod]
    public void CreateJwtTokenWithoutX5tTest()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = privateKey,
            SigningAlgorithm = SigningAlgorithm.RS256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } }
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsTrue(result.Token != null);

        // JWT tokens always have 2 dot separators between parts.
        Assert.IsTrue(result.Token.Count(i => i.Equals('.')) == 2);

    }

    /// <summary>
    /// Asymmetric.
    /// </summary>
    [TestMethod]
    public void CreateJwtTokenWithX5tTest()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = x5t,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = privateKey,
            SigningAlgorithm = SigningAlgorithm.RS256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } }
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsTrue(result.Token != null);

        // JWT tokens always have 2 dot separators between parts.
        Assert.IsTrue(result.Token.Count(i => i.Equals('.')) == 2);
    }
}