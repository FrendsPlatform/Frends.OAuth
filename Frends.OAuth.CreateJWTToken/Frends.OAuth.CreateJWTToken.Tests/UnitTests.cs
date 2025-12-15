using Frends.OAuth.CreateJWTToken.Definitions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace Frends.OAuth.CreateJWTToken.Tests;

[TestClass]
public class UnitTests
{
    private static readonly string KeysDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Keys");

    private static readonly string PrivateKey = File.ReadAllText(Path.Combine(KeysDirectory, "PK.pem"));
    private static readonly string Es512PrivateKey = File.ReadAllText(Path.Combine(KeysDirectory, "es512private.pem"));
    private static readonly string Es256PrivateKey = File.ReadAllText(Path.Combine(KeysDirectory, "es256private.pem"));
    private static readonly string Es384PrivateKey = File.ReadAllText(Path.Combine(KeysDirectory, "es384private.pem"));

    private const string X5T = "m5836ev678LlLGyFEdq+Ec71Inw=";

    Input? input;

    [TestMethod]
    public void KeysAreNotDisposed()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = Es512PrivateKey,
            SigningAlgorithm = SigningAlgorithm.ES512,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };
        var first = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(first);
        var second = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(second);
    }

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
            PrivateKey = PrivateKey,
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
    public void CreateJwtTokenWithoutX5TTest()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = PrivateKey,
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
    public void CreateJwtTokenWithX5TTest()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = X5T,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = PrivateKey,
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
            PrivateKey = PrivateKey,
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
            PrivateKey = PrivateKey,
            SigningAlgorithm = SigningAlgorithm.RS256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Claimer" } },
            CustomHeaders = new[] { new CustomHeader { Key = "kid", Value = "foobar" } }
        };

        var result = OAuth.CreateJWTToken(input);
        Assert.IsNotNull(result.Token);

        var parsedToken = ParseToken(result.Token, 0);
        Assert.AreEqual("foobar", parsedToken["kid"]);
    }

    [TestMethod]
    public void CreateJwtTokenWithEs256()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = Es256PrivateKey,
            SigningAlgorithm = SigningAlgorithm.ES256,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        var parsedToken = ParseToken(result.Token, 0);
        Assert.AreEqual("ES256", parsedToken["alg"]);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));
    }

    [TestMethod]
    public void CreateJwtTokenWithEs384()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = Es384PrivateKey,
            SigningAlgorithm = SigningAlgorithm.ES384,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        var parsedToken = ParseToken(result.Token, 0);
        Assert.AreEqual("ES384", parsedToken["alg"]);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));
    }

    [TestMethod]
    public void CreateJwtTokenWithEs512()
    {
        input = new Input
        {
            NotBefore = null,
            X509Thumbprint = null,
            Audience = "aud",
            Expires = DateTime.Now.AddMinutes(1),
            Issuer = "frends",
            PrivateKey = Es512PrivateKey,
            SigningAlgorithm = SigningAlgorithm.ES512,
            Claims = new[] { new JwtClaim { ClaimKey = "Name", ClaimValue = "Jefim4ik" } },
            CustomHeaders = Array.Empty<CustomHeader>()
        };

        var result = OAuth.CreateJWTToken(input);
        var parsedToken = ParseToken(result.Token, 0);
        Assert.AreEqual("ES512", parsedToken["alg"]);
        Assert.IsNotNull(result.Token);

        // JWT tokens always have 2 dot separators between parts.
        Assert.AreEqual(2, result.Token.Count(i => i.Equals('.')));
    }

    private static JObject ParseToken(string token, int splitIndex)
    {
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = (JwtSecurityToken)handler.ReadToken(token);
        return JObject.Parse(jsonToken.ToString().Split('.')[splitIndex]);
    }
}
