// Services/PlatformSuspiciousErrorDefinitions.cs
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace LogHunter.Services;

public sealed class PlatformSuspiciousErrorDefinition
{
    public required string Name { get; init; }
    public string? ContainsText { get; init; }
    public Regex? Regex { get; init; }

    public bool IsMatch(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return false;

        if (!string.IsNullOrWhiteSpace(ContainsText) &&
            message.IndexOf(ContainsText, StringComparison.OrdinalIgnoreCase) >= 0)
            return true;

        return Regex?.IsMatch(message) == true;
    }
}

public static class PlatformSuspiciousErrorDefinitions
{
    public static IReadOnlyList<PlatformSuspiciousErrorDefinition> All { get; } =
    [
        new PlatformSuspiciousErrorDefinition
        {
            Name = "Dangerous Request value",
            ContainsText = "A potentially dangerous Request."
        },
        new PlatformSuspiciousErrorDefinition
        {
            Name = "The file * does not exist",
            Regex = new Regex(@"The file\s+.+\s+does not exist\.", RegexOptions.IgnoreCase | RegexOptions.Compiled)
        }
    ];
}

