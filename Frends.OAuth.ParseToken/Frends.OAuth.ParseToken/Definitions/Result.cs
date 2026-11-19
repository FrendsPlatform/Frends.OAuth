using System;
using System.Collections.Generic;

namespace Frends.OAuth.ParseToken.Definitions;

/// <summary>
/// Result of parsing the token.
/// </summary>
public class Result
{
    /// <summary>
    /// Indicates if the task completed successfully.
    /// </summary>
    /// <example>true</example>
    public bool Success { get; set; }

    /// <summary>
    /// Unique identifier of the security token.
    /// </summary>
    /// <example>9b3250d8d5ee432</example>
    public string Id { get; set; }

    /// <summary>
    /// Issuer of the token.
    /// </summary>
    /// <example>https://identity.example.com/</example>
    public string Issuer { get; set; }

    /// <summary>
    /// Audience of the token.
    /// </summary>
    /// <example>orders-api</example>
    public string Audiences { get; set; }

    /// <summary>
    /// Identifier of the security key for this token.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SecurityKeyId { get; set; }

    /// <summary>
    /// Identifier of the signing key for this token.
    /// </summary>
    /// <example>gHVXsCt97WM6oGYVm0U0NUaGh7M5MF2CvysUNpShwcU21BAnkKU4Xg</example>
    public string SigningKeyId { get; set; }

    /// <summary>
    /// Gets the time from which the token is valid.
    /// </summary>
    /// <example>2026-11-12 10:00:00</example>
    public DateTime ValidFrom { get; set; }

    /// <summary>
    /// Gets the time until which the token is valid.
    /// </summary>
    /// <example>2026-11-12 11:00:00</example>
    public DateTime ValidTo { get; set; }

    /// <summary>
    /// A dictionary of all claims in the token.
    /// </summary>
    /// <example>
    /// {
    ///     {"nickname", "foobar"},
    ///     {"name", "Foo Bar"},
    ///     {"iss", "https://identity.example.com/"}
    /// }
    /// </example>
    public Dictionary<string, dynamic> Claims { get; set; }

    /// <summary>
    /// Error that occurred during task execution.
    /// </summary>
    /// <example>object { string Message, Exception AdditionalInfo }</example>
    public Error Error { get; set; }
}
