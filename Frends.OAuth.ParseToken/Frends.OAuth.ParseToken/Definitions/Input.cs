using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.OAuth.ParseToken.Definitions;

/// <summary>
/// Input parameters.
/// </summary>
public class Input
{
    internal string GetToken()
    {
        if (string.IsNullOrEmpty(AuthHeaderOrToken))
            throw new Exception("AuthHeader did not contain a Bearer token");

        if (AuthHeaderOrToken.StartsWith("Bearer ", StringComparison.CurrentCultureIgnoreCase))
            return AuthHeaderOrToken.Substring("Bearer ".Length).Trim();

        return AuthHeaderOrToken;
    }

    /// <summary>
    /// Either the JWT token or the Authorization header value through #trigger.data.httpHeaders["Authorization"].
    /// </summary>
    /// <example>#trigger.data.httpHeaders[\"Authorization\"]</example>
    [DisplayFormat(DataFormatString = "Expression")]
    [DefaultValue("#trigger.data.httpHeaders[\"Authorization\"]")]
    public string AuthHeaderOrToken { get; set; }

    /// <summary>
    /// The expected Audiences of the token, e.g. ClientId.
    /// </summary>
    /// <example>fIVLouKUZasdYP3tdO9D3dwd6ZNS9Be</example>
    [DefaultValue("")]
    [DisplayFormat(DataFormatString = "Text")]
    public string Audience { get; set; }

    /// <summary>
    /// The expected Issuer of the token.
    /// </summary>
    /// <example>https://xyz.eu.auth0.com/</example>
    [DisplayFormat(DataFormatString = "Text")]
    [DefaultValue("https://xyz.eu.auth0.com/")]
    public string Issuer { get; set; }

    /// <summary>
    /// The configuration source.
    /// </summary>
    /// <example>Static</example>
    [DefaultValue(ConfigurationSource.Static)]
    public ConfigurationSource ConfigurationSource { get; set; }

    /// <summary>
    /// The URL where the .well-known configuration for the issuer is located.
    /// </summary>
    /// <example>https://xyz.eu.auth0.com/.well-known/openid-configuration</example>
    [DisplayFormat(DataFormatString = "Text")]
    [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.WellKnownConfigurationUrl)]
    [DefaultValue("https://xyz.eu.auth0.com/.well-known/openid-configuration")]
    public string WellKnownConfigurationUrl { get; set; }

    /// <summary>
    /// Static signing keys to use, can be found in the jwks_uri from the .well-known openid-configurations.
    /// </summary>
    /// <example>o80vbR0ZfMhjZWfqwPUGNkcIeUcweFyzB2S2T</example>
    [DisplayFormat(DataFormatString = "Text")]
    [UIHint(nameof(ConfigurationSource), "", ConfigurationSource.Static)]
    public string StaticJwksConfiguration { get; set; }
}