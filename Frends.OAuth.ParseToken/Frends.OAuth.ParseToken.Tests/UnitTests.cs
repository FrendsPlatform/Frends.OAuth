using Frends.OAuth.ParseToken.Definitions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace Frends.OAuth.ParseToken.Tests;

[TestClass]
public class UnitTests
{
    private static readonly string _authHeader = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/AuthHeader.txt"));
    private static readonly string _authHeaderWithArrayTypeClaim = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/AuthHeaderWithArrayTypeClaim.txt"));
    readonly JObject JwkKeys = JObject.Parse(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/JwkKeys.json")));
    private static Input _input = new();
    private static Options _options = new();

    [TestInitialize]
    public void Init()
    {
        _input = new Input()
        {
            Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
            AuthHeaderOrToken = _authHeader,
            ConfigurationSource = ConfigurationSource.WellKnownConfigurationUrl,
            Issuer = "https://frends.eu.auth0.com/",
            StaticJwksConfiguration = null,
            WellKnownConfigurationUrl = "https://frends.eu.auth0.com/.well-known/openid-configuration"
        };

        _options = new Options()
        {
            SkipAudienceValidation = false,
            DecryptionKey = null,
            SkipIssuerValidation = true,
            SkipLifetimeValidation = true,
            DecryptToken = false,
        };
    }

    [TestMethod]
    public async Task ParseTokenTest_WithWellKnownUri()
    {
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_WithStaticConfiguration()
    {
        _input.StaticJwksConfiguration = JwkKeys.ToString();
        _input.ConfigurationSource = ConfigurationSource.Static;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_WithArrayTypeClaim()
    {
        _input.AuthHeaderOrToken = _authHeaderWithArrayTypeClaim;
        _input.ConfigurationSource = ConfigurationSource.Static;
        _input.StaticJwksConfiguration = JwkKeys.ToString();
        var result = await OAuth.ParseToken(_input, _options, default);
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
        _input.Audience = "Foo";
        await Assert.ThrowsExceptionAsync<SecurityTokenInvalidAudienceException>(async () => await OAuth.ParseToken(_input, _options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_Invalid_AuthHeaderOrToken_Throw()
    {
        _input.AuthHeaderOrToken = "Foo";
        await Assert.ThrowsExceptionAsync<SecurityTokenMalformedException>(async () => await OAuth.ParseToken(_input, _options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_Issuer_AnotherIssuer()
    {
        _input.Issuer = "Foo";
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_Issuer_Static()
    {
        _input.StaticJwksConfiguration = JwkKeys.ToString();
        _input.ConfigurationSource = ConfigurationSource.Static;
        _input.Issuer = "Foo";
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipAudienceValidation_True()
    {
        _options.SkipAudienceValidation = true;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipIssuerValidation_False()
    {
        _options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_SkipLifetimeValidation_False()
    {
        _options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Zero_ExpiredToken_Throws()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(60));
        _options.SkipLifetimeValidation = false;
        _options.ClockSkewSeconds = 0;
        await Assert.ThrowsExceptionAsync<SecurityTokenExpiredException>(async () => await OAuth.ParseToken(_input, _options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Larger_Than_Expiry_Passes()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(60));
        _options.SkipLifetimeValidation = false;
        _options.ClockSkewSeconds = 300;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.Claims.Count > 0);
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Smaller_Than_Expiry_Throws()
    {
        SetupExpiredToken(TimeSpan.FromSeconds(600));
        _options.SkipLifetimeValidation = false;
        _options.ClockSkewSeconds = 300;
        await Assert.ThrowsExceptionAsync<SecurityTokenExpiredException>(async () => await OAuth.ParseToken(_input, _options, default));
    }

    [TestMethod]
    public async Task ParseTokenTest_ClockSkew_Ignored_When_SkipLifetimeValidation_True()
    {
        SetupExpiredToken(TimeSpan.FromHours(1));
        _options.SkipLifetimeValidation = true;
        _options.ClockSkewSeconds = 0;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.Claims.Count > 0);
    }

    // Creates a token signed with a generated key that expired the given time ago and configures static JWKS for it.
    private static void SetupExpiredToken(TimeSpan expiredAgo)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "test-key" };
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Audience = _input.Audience,
            Issuer = _input.Issuer,
            NotBefore = now - expiredAgo - TimeSpan.FromMinutes(10),
            IssuedAt = now - expiredAgo - TimeSpan.FromMinutes(10),
            Expires = now - expiredAgo,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        };
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);

        var publicKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "test-key" };
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
        _input.AuthHeaderOrToken = token;
        _input.ConfigurationSource = ConfigurationSource.Static;
        _input.StaticJwksConfiguration = new JObject { ["keys"] = new JArray(JObject.Parse(System.Text.Json.JsonSerializer.Serialize(new { kty = jwk.Kty, kid = jwk.Kid, use = "sig", alg = "RS256", n = jwk.N, e = jwk.E }))) }.ToString();
    }

    [TestMethod]
    public async Task ParseTokenTest_DecryptToken_True()
    {
        _options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }
}