namespace Frends.OAuth.CreateJWTToken.Definitions;

/// <summary>
/// Class for a customer JWT header.
/// </summary>
public class CustomHeader
{
    /// <summary>
    /// Key of the header.
    /// </summary>
    /// <example>kid</example>
    public string Key { get; set; }

    /// <summary>
    /// Value for the header.
    /// </summary>
    /// <example>fsabijfbodsafadsfn</example>
    public string Value { get; set; }
}
