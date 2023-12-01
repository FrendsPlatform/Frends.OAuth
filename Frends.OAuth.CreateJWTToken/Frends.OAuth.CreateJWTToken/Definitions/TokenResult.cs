namespace Frends.OAuth.CreateJWTToken.Definitions;
/// <summary>
/// Return token.
/// </summary>
public class TokenResult
{

    internal TokenResult(string token)
    {
        Token = token;
    }

    /// <summary>
    /// Token.
    /// </summary>
    /// <example>"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiQ2xhaW1lciIsIm5iZiI6sTY1NjQ5OTk3NiwiZXhwIjoxNjU2NTAwMDMyLCJpYXQiOjE2NTY0OTk5NzYsImlzckI6ImZyZW5kcyIsImF1ZCI6ImF1ZCJ9.qImoi_fSi2BL4aoxIvvaGUVoM7usX40Mrdodh4yD8BY"</example>
    public string Token { get; private set; }
}