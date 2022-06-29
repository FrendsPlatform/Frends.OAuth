using System.Collections.Generic;

namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Return token.
/// </summary>
public class Result
{
    /// <summary>
    /// Return token.
    /// </summary>
    public List<TokenResult> Results { get; internal set; }
}