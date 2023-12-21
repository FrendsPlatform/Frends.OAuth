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
public class OAuth
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
        bool isSymmetric = input.SigningAlgorithm.ToString().StartsWith("HS");
        using var rsa = RSA.Create();
        using var ecdsa = ECDsa.Create();

        // If signing algorithm is symmetric, key is not in PEM format and no stream is used to read it.
        if (isSymmetric)
        {
            var securityKey = Encoding.UTF8.GetBytes(input.PrivateKey);
            var symmetricSecurityKey = new SymmetricSecurityKey(securityKey);
            signingCredentials = new SigningCredentials(symmetricSecurityKey, input.SigningAlgorithm.ToString());
        }
        else if (input.SigningAlgorithm.ToString().StartsWith("RS"))
        // Default is to use stream and assume PEM format.
        {
            rsa.ImportFromPem(input.PrivateKey);

            signingCredentials = new SigningCredentials(key: new RsaSecurityKey(rsa), algorithm: input.SigningAlgorithm.ToString())
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
        }
        else
        {
            ecdsa.ImportFromPem(input.PrivateKey);
            signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), input.SigningAlgorithm.ToString());
        }
        return new TokenResult(CreateToken(signingCredentials, input, isSymmetric));
    }

    private static string CreateToken(SigningCredentials signingCredentials, Input input, bool usesSymmetricAlgorithm)
    {
        var handler = new JwtSecurityTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
        var claims = new ClaimsIdentity();
        JwtSecurityToken secToken;

        if (input.Claims != null)
            foreach (var claim in input.Claims)
                claims.AddClaim(new Claim(claim.ClaimKey, claim.ClaimValue));

        // x5t Header can be used only when the signing algorithm is asymmetric
        if (!usesSymmetricAlgorithm && !string.IsNullOrEmpty(input.X509Thumbprint))
        {
            long expires = DateTimeToUnixTimeStamp(input.Expires ?? DateTime.Now.AddHours(1));
            long notBefore = DateTimeToUnixTimeStamp(input.NotBefore ?? DateTime.Now);
            long issuedAt = DateTimeToUnixTimeStamp(DateTime.Now);

            JwtHeader header = new(signingCredentials)
            {
                { "x5t", input.X509Thumbprint }
            };

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

        return handler.WriteToken(secToken).ToString();
    }

    private static long DateTimeToUnixTimeStamp(DateTime dt)
    {
        return ((DateTimeOffset)dt).ToUniversalTime().ToUnixTimeSeconds();
    }
}