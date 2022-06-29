using System;
using System.Collections.Generic;
using System.ComponentModel;
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
    /// Create OAuth JWTToken.
    /// [Documentation](https://tasks.frends.com/tasks/frends-tasks/Frends.OAuth.CreateJWTToken
    /// </summary>
    /// <param name="input">Input parameters</param>
    /// <returns>List { string Token }</returns>
    public static Result CreateJWTToken([PropertyTab] Input input)
    {
        SigningCredentials signingCredentials;
        bool isSymmetric = input.SigningAlgorithm.ToString().StartsWith("HS");

        // If signing algorithm is symmetric, key is not in PEM format and no stream is used to read it.
        if (isSymmetric)
        {
            var securityKey = Encoding.UTF8.GetBytes(input.PrivateKey);
            var symmetricSecurityKey = new SymmetricSecurityKey(securityKey);
            signingCredentials = new SigningCredentials(symmetricSecurityKey, MapSecurityAlgorithm(input.SigningAlgorithm.ToString()));
        }
        else
        // Default is to use stream and assume PEM format.
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(input.PrivateKey);

            signingCredentials = new SigningCredentials(key: new RsaSecurityKey(rsa), algorithm: input.SigningAlgorithm.ToString())
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
        }
        return new Result { Results = CreateToken(signingCredentials, input, isSymmetric) };
    }

    private static List<TokenResult> CreateToken(SigningCredentials signingCredentials, Input input, bool usesSymmetricAlgorithm)
    {
        var result = new List<TokenResult>();
        var handler = new JwtSecurityTokenHandler();
        var claims = new ClaimsIdentity();
        JwtSecurityToken secToken;

        if (input.Claims != null)
            foreach (var claim in input.Claims)
                claims.AddClaim(new Claim(claim.ClaimKey, claim.ClaimValue));

        try
        {
            // x5t Header can be used only when the signing algorithm is asymmetric
            if (!usesSymmetricAlgorithm && !string.IsNullOrEmpty(input.X509Thumbprint))
            {
                long expires = DateTimeToUnixTimeStamp(input.Expires ?? DateTime.Now.AddHours(1));
                long notBefore = DateTimeToUnixTimeStamp(input.NotBefore ?? DateTime.Now);
                long issuedAt = DateTimeToUnixTimeStamp(DateTime.Now);

                JwtHeader header = new JwtHeader(signingCredentials);
                header.Add("x5t", input.X509Thumbprint);

                JwtPayload payload = new JwtPayload();
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
                    Expires = input.Expires,
                    NotBefore = input.NotBefore,
                    Subject = claims,
                    SigningCredentials = signingCredentials,
                });
            }

            result.Add(new TokenResult(handler.WriteToken(secToken)));
            return result;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.ToString());
        }
    }

    private static string MapSecurityAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            "RS256" => SecurityAlgorithms.RsaSha256Signature,
            "RS384" => SecurityAlgorithms.RsaSha384Signature,
            "RS512" => SecurityAlgorithms.RsaSha512Signature,
            "HS256" => SecurityAlgorithms.HmacSha256Signature,
            "HS384" => SecurityAlgorithms.HmacSha384Signature,
            "HS512" => SecurityAlgorithms.HmacSha512Signature,
            _ => SecurityAlgorithms.RsaSha256Signature,
        };
    }

    private static long DateTimeToUnixTimeStamp(DateTime dt)
    {
        return ((DateTimeOffset)dt).ToUniversalTime().ToUnixTimeSeconds();
    }
}