using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Frends.OAuth.CreateJWTToken.Definitions;
using Microsoft.IdentityModel.Tokens;

namespace Frends.OAuth.CreateJWTToken;

/// <summary>
/// OAuth operation task.
/// </summary>
public static class OAuth
{
    /// <summary>
    /// Create JSON Web Token.
    /// [Documentation](https://tasks.frends.com/tasks/frends-tasks/Frends.OAuth.CreateJWTToken)
    /// </summary>
    /// <param name="input">Input parameters</param>
    /// <returns>Object { string Token }</returns>
    public static TokenResult CreateJWTToken(Input input)
    {
        SigningCredentials signingCredentials;
        using var rsa = RSA.Create();
        using var ecdsa = ECDsa.Create() ?? throw new InvalidOperationException("ECDsa.Create() returned null");

        switch (input.SigningAlgorithm.ToString())
        {
            case { } s when s.StartsWith("HS"): // symmetric
                var securityKey = Encoding.UTF8.GetBytes(input.PrivateKey);
                var symmetricSecurityKey = new SymmetricSecurityKey(securityKey);
                signingCredentials = new SigningCredentials(symmetricSecurityKey, input.SigningAlgorithm.ToString());
                break;
            case { } s when s.StartsWith("RS"): // asymmetric
                rsa.ImportFromPem(input.PrivateKey);
                signingCredentials =
                    new SigningCredentials(
                        new RsaSecurityKey(rsa)
                        {
                            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                        },
                        input.SigningAlgorithm.ToString());
                break;
            case { } s when s.StartsWith("ES"): // asymmetric
                ecdsa.ImportFromPem(input.PrivateKey);
                signingCredentials =
                    new SigningCredentials(
                        new ECDsaSecurityKey(ecdsa)
                        {
                            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                        },
                        input.SigningAlgorithm.ToString());
                break;
            default:
                throw new ArgumentException($"Signing algorithm {input.SigningAlgorithm} is not supported.");
        }

        return new TokenResult(CreateToken(signingCredentials, input));
    }

    private static string CreateToken(SigningCredentials signingCredentials, Input input)
    {
        bool usesSymmetricHsAlgorithm = input.SigningAlgorithm.ToString().StartsWith("HS");
        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var claims = new ClaimsIdentity();
        JwtSecurityToken secToken;

        if (input.Claims != null)
            foreach (var claim in input.Claims)
                claims.AddClaim(new Claim(claim.ClaimKey, claim.ClaimValue));

        // x5t Header can be used only when the signing algorithm is asymmetric
        if (!usesSymmetricHsAlgorithm && !string.IsNullOrEmpty(input.X509Thumbprint))
        {
            long expires = DateTimeToUnixTimeStamp(input.Expires ?? DateTime.Now.AddHours(1));
            long notBefore = DateTimeToUnixTimeStamp(input.NotBefore ?? DateTime.Now);
            long issuedAt = DateTimeToUnixTimeStamp(DateTime.Now);

            JwtHeader header = new(signingCredentials) { { "x5t", input.X509Thumbprint } };

            var payload = new JwtPayload();
            payload.AddClaims(claims.Claims);
            payload.Add("nbf", notBefore);
            payload.Add("exp", expires);
            payload.Add("iat", issuedAt); // Static property, always DateTime.Now as unix timestamp
            payload.Add("iss", input.Issuer);
            payload.Add("aud", input.Audience);

            secToken = new JwtSecurityToken(header, payload);
        }
        else
        {
            secToken = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor
            {
                Issuer = input.Issuer,
                Audience = input.Audience,
                IssuedAt = DateTime.UtcNow,
                Expires = input.Expires,
                NotBefore = input.NotBefore,
                Subject = claims,
                SigningCredentials = signingCredentials,
            });
        }

        foreach (var customHeader in input.CustomHeaders)
            secToken.Header.Add(customHeader.Key, customHeader.Value);

        return handler.WriteToken(secToken);
    }

    private static long DateTimeToUnixTimeStamp(DateTime dt)
    {
        return ((DateTimeOffset)dt).ToUniversalTime().ToUnixTimeSeconds();
    }
}
