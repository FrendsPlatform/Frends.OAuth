using Microsoft.VisualStudio.TestTools.UnitTesting;
using Frends.OAuth.ParseToken.Definitions;
using Newtonsoft.Json.Linq;

namespace Frends.OAuth.ParseToken.Tests;

[TestClass]
public class UnitTests
{
    private static readonly string AuthHeader = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/AuthHeader.txt"));
    readonly JObject JwkKeys = JObject.Parse(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Files/JwkKeys.json")));

    Input? input;
    Options? options;

    /// <summary>
    /// Parse token with WellKnownConfigurationUrl.
    /// </summary>
    [TestMethod]
    public async Task TokenWithWellKnownUriTest()
    {
        input = new Input
        {
            StaticJwksConfiguration = null,
            Issuer = "https://frends.eu.auth0.com/",
            Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
            AuthHeaderOrToken = AuthHeader,
            ConfigurationSource = ConfigurationSource.WellKnownConfigurationUrl,
            WellKnownConfigurationUrl = "https://frends.eu.auth0.com/.well-known/openid-configuration"
        };

        options = new Options
        {
            SkipAudienceValidation = false,
            DecryptionKey = null,
            SkipIssuerValidation = true,
            SkipLifetimeValidation = true,
            DecryptToken = false,
        };

        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsNotNull(result.SecurityKeyId != null || result.SigningKeyId != null);
    }

    /// <summary>
    /// Parse token with Static ConfigurationSource.
    /// </summary>
    [TestMethod]
    public async Task TokenWithStaticConfigurationTest()
    {
        input = new Input
        {
            StaticJwksConfiguration = JwkKeys.ToString(),
            Issuer = "https://frends.eu.auth0.com/",
            Audience = "fIVLouKUZihXfYP3tdO9D3dwd6ZNS9Be",
            AuthHeaderOrToken = AuthHeader,
            ConfigurationSource = ConfigurationSource.Static,
            WellKnownConfigurationUrl = null
        };

        options = new Options
        {
            SkipAudienceValidation = false,
            DecryptionKey = null,
            SkipIssuerValidation = true,
            SkipLifetimeValidation = true,
            DecryptToken = false,
        };
        var result = await OAuth.ParseToken(input, options, default);
        Assert.IsNotNull(result.SecurityKeyId != null || result.SigningKeyId != null);
    }
}