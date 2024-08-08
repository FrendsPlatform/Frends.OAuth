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
        await Assert.ThrowsExceptionAsync<ArgumentException>(async () => await OAuth.ParseToken(_input, _options, default));
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
    public async Task ParseTokenTest_DecryptToken_True()
    {
        _options.SkipIssuerValidation = true;
        var result = await OAuth.ParseToken(_input, _options, default);
        Assert.IsTrue(result.SecurityKeyId != null || result.SigningKeyId != null);
        Assert.IsTrue(result.Claims.Count > 1);
    }
}