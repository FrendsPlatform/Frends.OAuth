using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Frends.OAuth.ParseToken.Definitions;
/// <summary>
/// Return token.
/// </summary>
public class ParseResult
{
    /// <summary>
    /// A claim-based identity parsed from the token.
    /// </summary>
    /// <example>nickname:, name:, picture:, updated_at:, iss:, aud:, iat:, exp:, at_hash:, nonce:</example>
    public ClaimsPrincipal ClaimsPrincipal { get; set; }

    /// <summary>
    /// A validated security token.
    /// </summary>
    /// <example>{{"typ":"JWT","alg":"RS256","kid":"MTUyRjI1ASDTg4NTI3OTQzRTczRTU3NUQ3NzgyODhBRDZBNTU3Mw"}.{"nickname":"test","name":"test@hiq.fi","picture":"foo.png","updated_at":"2018-10-18T10:10:19.443Z","iss":"https://foo.eu.auth0.com/","sub":"auth0|5bc8404a8f65fb7f2934cd53","aud":"fIVLouKSAihXfYP3tdO9D3dwd6ZNS9Be","iat":1539857423,"exp":1539893423,"at_hash":"YsBWM1fCez-FIRvi4wpz1A","nonce":"3.BfZpNwp3Ju4wzkjXX1gkPvrpru4102"}}</example>
    public SecurityToken Token { get; set; }
}