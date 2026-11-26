using Xunit;

namespace LogHunter.Tests;

/// <summary>
/// Tests that read or replace the static IpIntelStore snapshot share this collection, so xUnit
/// runs them one after another instead of in parallel.
/// </summary>
[CollectionDefinition(Name)]
public sealed class SharedIpIntelState
{
    public const string Name = "Shared IpIntelStore snapshot";
}
