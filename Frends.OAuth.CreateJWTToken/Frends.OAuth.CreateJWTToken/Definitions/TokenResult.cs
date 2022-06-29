namespace Frends.OAuth.CreateJWTToken.Definitions;
/// <summary>
/// Return token.
/// </summary>
public class TokenResult
{
    /// <summary>
    /// Token.
    /// </summary>
    public string Token { get; private set; }

    internal TokenResult(string Status)
    {
        Token = Status;
    }
}