using Frends.OAuth.CreateJWTToken.Definitions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

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
            PrivateKey = privateKey,
            SigningAlgorithm = SigningAlgorithm.HS256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));
    }

    /// <summary>
    /// Create without X509Thumbprint -> Asymmetric.
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
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));

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
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));
    }

    /// <summary>
    /// Not Before is not added if left out.
    /// </summary>
    [TestMethod]
    public void CreateJwtTokenWithoutNbf()
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
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        var parsedToken = ParseToken(result.Token, 1);
        Assert.IsNull(parsedToken["nbf"]);
    }

    /// <summary>
    /// Custom headers are added to the JWT header.
    /// </summary>
    [TestMethod]
    public void CreateJwtTokenWithCustomHeaders()
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
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } },
            CustomHeaders = new CustomHeader[] { new CustomHeader { Key = "kid", Value = "fosagfofssago" } }
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        var parsedToken = ParseToken(result.Token, 0);
        Assert.AreEqual("fosagfofssago", parsedToken["kid"]);
    }

    private static JObject ParseToken(string token, int splitIndex)
    {
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = (JwtSecurityToken)handler.ReadToken(token);
        return JObject.Parse(jsonToken.ToString().Split('.')[splitIndex]);
    }
}