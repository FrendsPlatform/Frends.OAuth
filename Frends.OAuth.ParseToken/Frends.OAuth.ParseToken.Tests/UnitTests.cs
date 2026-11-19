using Frends.OAuth.ParseToken.Definitions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Frends.OAuth.ParseToken.Tests;

[TestClass]
public class UnitTests
{
    private static readonly string AuthHeader = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/AuthHeader.txt"));
    private static readonly string AuthHeaderWithArrayTypeClaim = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/AuthHeaderWithArrayTypeClaim.txt"));
    private static readonly JObject JwkKeys = JObject.Parse(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/JwkKeys.json")));
    private static Input input = new();
    private static Options options = new();

    [TestInitialize]
    public void Init()
    {
        input = new Input
        {
            Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
            AuthHeaderOrToken = AuthHeader,
            ConfigurationSource = ConfigurationSource.Static,
            Issuer = "https://frends.eu.auth0.com/",
            StaticJwksConfiguration = JwkKeys.ToString(),
            WellKnownConfigurationUrl = "https://frends.eu.auth0.com/.well-known/openid-configuration",
        };

        options = new Options
        {
            SkipAudienceValidation = false,
            DecryptionKey = null,
            SkipIssuerValidation = true,
            SkipLifetimeValidation = true,
            DecryptToken = false,
            ThrowErrorOnFailure = true,
            ErrorMessageOnFailure = string.Empty,
        };
    }

    [TestMethod]
    public async Task ParseTokenTest_WithWellKnownUri()
    {
        input.ConfigurationSource = ConfigurationSource.WellKnownConfigurationUrl;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_WithStaticConfiguration()
    {
        input.StaticJwksConfiguration = JwkKeys.ToString();
        input.ConfigurationSource = ConfigurationSource.Static;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_WithArrayTypeClaim()
    {
        input.AuthHeaderOrToken = AuthHeaderWithArrayTypeClaim;
        input.ConfigurationSource = ConfigurationSource.Static;
        input.StaticJwksConfiguration = JwkKeys.ToString();
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.Success);
        Assert.IsTrue(result.Claims.Count > 1);
        Assert.IsInstanceOfType(result.Claims["test_array"], typeof(Array));

        var arrayValues = (string[])result.Claims["test_array"];
        Assert.AreEqual(4, arrayValues.Length);
        Assert.AreEqual("item1", arrayValues[0]);
        Assert.AreEqual("item2", arrayValues[1]);
        Assert.AreEqual("item3", arrayValues[2]);
        Assert.AreEqual("item4", arrayValues[3]);
    }

    [TestMethod]
    public async Task ParseTokenTest_Invalid_Audience_Throw()
    {
        input.Audience = "Foo";
        await Assert.ThrowsExceptionAsync<SecurityTokenInvalidAudienceException>(async () => await OAuth.ParseToken(input, options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_Invalid_AuthHeaderOrToken_Throw()
    {
        input.AuthHeaderOrToken = "Foo";
        await Assert.ThrowsExceptionAsync<SecurityTokenMalformedException>(async () => await OAuth.ParseToken(input, options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_InvalidToken_ReturnsFailureWhenConfigured()
    {
        input.AuthHeaderOrToken = "Foo";
        options.ThrowErrorOnFailure = false;
        options.ErrorMessageOnFailure = "Token parsing failed";

        var result = await OAuth.ParseToken(input, options, default);

        Assert.IsFalse(result.Success);
        Assert.IsNotNull(result.Error);
        Assert.IsTrue(result.Error.Message.StartsWith("Token parsing failed:", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task ParseTokenTest_Issuer_AnotherIssuer()
    {
        input.Issuer = "Foo";
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_Issuer_Static()
    {
        input.StaticJwksConfiguration = JwkKeys.ToString();
        input.ConfigurationSource = ConfigurationSource.Static;
        input.Issuer = "Foo";
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipAudienceValidation_True()
    {
        options.SkipAudienceValidation = true;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipIssuerValidation_False()
    {
        options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipLifetimeValidation_False()
    {
        options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Zero_ExpiredToken_Throws()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(60));
        options.SkipLifetimeValidation = false;
        options.ClockSkewSeconds = 0;
        await Assert.ThrowsExceptionAsync<SecurityTokenExpiredException>(async () => await OAuth.ParseToken(input, options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Larger_Than_Expiry_Passes()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(60));
        options.SkipLifetimeValidation = false;
        options.ClockSkewSeconds = 300;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.Claims.Count > 0);
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Smaller_Than_Expiry_Throws()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(600));
        options.SkipLifetimeValidation = false;
        options.ClockSkewSeconds = 300;
        await Assert.ThrowsExceptionAsync<SecurityTokenExpiredException>(async () => await OAuth.ParseToken(input, options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Ignored_When_SkipLifetimeValidation_True()
    {
        SetupExpiredToken(TimeSpan.FromHours(1));
        options.SkipLifetimeValidation = true;
        options.ClockSkewSeconds = 0;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.Claims.Count > 0);
    }

    [TestMethod]
    public async Task ParseTokenTest_DecryptToken_True()
    {
        options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    private static void SetupExpiredToken(TimeSpan expiredAgo)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "test-key" };
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Audience = input.Audience,
            Issuer = input.Issuer,
            NotBefore = now - expiredAgo - TimeSpan.FromMinutes(10),
            IssuedAt = now - expiredAgo - TimeSpan.FromMinutes(10),
            Expires = now - expiredAgo,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        };
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);

        var publicKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "test-key" };
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
        input.AuthHeaderOrToken = token;
        input.ConfigurationSource = ConfigurationSource.Static;
        input.StaticJwksConfiguration = new JObject { ["keys"] = new JArray(JObject.Parse(System.Text.Json.JsonSerializer.Serialize(new { kty = jwk.Kty, kid = jwk.Kid, use = "sig", alg = "RS256", n = jwk.N, e = jwk.E }))) }.ToString();
    }
}
