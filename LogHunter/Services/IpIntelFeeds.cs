using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;

namespace LogHunter.Services;

/// <summary>What an IP range belongs to. Category decides how operators should read a hit.</summary>
internal enum IpIntelCategory
{
    /// <summary>CDN / WAF edge: traffic from here hides the real client (look at IIS X-Forwarded-For).</summary>
    Cdn,
    /// <summary>Corporate forward proxy (Zscaler, Netskope): real users behind it, not an attacker by itself.</summary>
    CorporateProxy,
    /// <summary>Vendor health checkers / monitors.</summary>
    HealthCheck,
}

/// <param name="Likely">True when the range comes from the vendor's network (ASN) rather than a
/// published edge list: it is the vendor, but not necessarily the customer's CDN.</param>
internal sealed record IpIntelLabel(string Provider, string Service, IpIntelCategory Category, string FeedId, bool Likely = false)
{
    public string Badge => Category switch
    {
        IpIntelCategory.Cdn => Likely ? $"{Provider} network (likely)" : $"{Provider} edge",
        IpIntelCategory.CorporateProxy => $"{Provider} proxy",
        _ => $"{Provider} health check",
    };

    // Lower wins when several labels cover one IP (e.g. CLOUDFRONT_ORIGIN_FACING inside CLOUDFRONT,
    // or the Akamai Origin IP ACL list inside Akamai's network ranges).
    public int Priority => (Likely ? 10 : 0) + Category switch
    {
        IpIntelCategory.Cdn => Service.Contains("ORIGIN", StringComparison.OrdinalIgnoreCase) ? 0 : 1,
        IpIntelCategory.HealthCheck => 2,
        _ => 3,
    };
}

/// <param name="DiscoveryPattern">Regex run on the body of Url to find the real download URL
/// (Azure publishes a new file name every week).</param>
/// <param name="DiscoveredHost">Only host the discovered URL may point to.</param>
/// <param name="Reduce">Shrinks the downloaded body before it is validated and stored.</param>
internal sealed record IpIntelFeed(
    string Id,
    string Provider,
    string Url,
    HttpMethod Method,
    string? PostBody,
    Func<string, IEnumerable<(string Cidr, IpIntelLabel Label)>> Parse,
    string? DiscoveryPattern = null,
    string? DiscoveredHost = null,
    Func<string, string>? Reduce = null,
    TimeSpan? RefreshAfter = null);

/// <summary>
/// Vendor-published range feeds (no auth, no key). Only CDN / proxy / health-check services are
/// kept: broad cloud ranges (AMAZON, EC2, Cloudflare AS13335 as a whole) host attackers too and must
/// never be labelled as CDN. Research and sources: docs/research/cdn/a-vendor-feeds.md.
/// </summary>
internal static class IpIntelFeeds
{
    public static readonly IReadOnlyList<IpIntelFeed> All = new[]
    {
        new IpIntelFeed("cloudflare-v4", "Cloudflare", "https://www.cloudflare.com/ips-v4", HttpMethod.Get, null,
            body => Lines(body, Cdn("Cloudflare", "edge", "cloudflare-v4"))),
        new IpIntelFeed("cloudflare-v6", "Cloudflare", "https://www.cloudflare.com/ips-v6", HttpMethod.Get, null,
            body => Lines(body, Cdn("Cloudflare", "edge", "cloudflare-v6"))),
        new IpIntelFeed("aws", "AWS", "https://ip-ranges.amazonaws.com/ip-ranges.json", HttpMethod.Get, null, ParseAws),
        new IpIntelFeed("akamai-v4", "Akamai", "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt", HttpMethod.Get, null,
            body => Lines(body, Cdn("Akamai", "Origin IP ACL", "akamai-v4"))),
        new IpIntelFeed("akamai-v6", "Akamai", "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv6_CIDRs.txt", HttpMethod.Get, null,
            body => Lines(body, Cdn("Akamai", "Origin IP ACL", "akamai-v6"))),
        new IpIntelFeed("imperva", "Imperva", "https://my.imperva.com/api/integration/v1/ips", HttpMethod.Post, "resp_format=json",
            body => JsonArrays(body, Cdn("Imperva", "edge", "imperva"), "ipRanges", "ipv6Ranges")),
        new IpIntelFeed("fastly", "Fastly", "https://api.fastly.com/public-ip-list", HttpMethod.Get, null,
            body => JsonArrays(body, Cdn("Fastly", "edge", "fastly"), "addresses", "ipv6_addresses")),
        new IpIntelFeed("f5xc", "F5 Distributed Cloud", "https://docs.cloud.f5.com/docs-v2/downloads/platform/reference/network-cloud-ref/ips-domains.json", HttpMethod.Get, null, ParseF5),
        new IpIntelFeed("zscaler", "Zscaler", "https://config.zscaler.com/api/zscaler.net/cenr/json", HttpMethod.Get, null, ParseZscaler),
        // Akamai's public list only covers customers with Origin IP ACL; its networks cover the rest (likely).
        new IpIntelFeed("akamai-as20940", "Akamai", "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS20940", HttpMethod.Get, null,
            body => ParseRipeStatPrefixes(body, new IpIntelLabel("Akamai", "AS20940", IpIntelCategory.Cdn, "akamai-as20940", Likely: true))),
        new IpIntelFeed("akamai-as16625", "Akamai", "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS16625", HttpMethod.Get, null,
            body => ParseRipeStatPrefixes(body, new IpIntelLabel("Akamai", "AS16625", IpIntelCategory.Cdn, "akamai-as16625", Likely: true))),
        new IpIntelFeed("azure-frontdoor", "Azure Front Door", "https://www.microsoft.com/en-us/download/details.aspx?id=56519", HttpMethod.Get, null,
            body => Lines(body, Cdn("Azure Front Door", "AzureFrontDoor.Backend", "azure-frontdoor")),
            DiscoveryPattern: @"https://download\.microsoft\.com/download/[^""\\\s]+/ServiceTags_Public_\d{8}\.json",
            DiscoveredHost: "download.microsoft.com",
            Reduce: ReduceAzureServiceTags,
            RefreshAfter: TimeSpan.FromDays(3)),
    };

    /// <summary>Vendors without a machine-readable feed; reviewed with each release.</summary>
    public static readonly IReadOnlyList<(string Cidr, IpIntelLabel Label)> Static = BuildStatic();

    public static IEnumerable<(string Cidr, IpIntelLabel Label)> ParseAws(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var result = new List<(string, IpIntelLabel)>();
        foreach (var (array, field) in new[] { ("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix") })
        {
            if (!doc.RootElement.TryGetProperty(array, out var list))
                continue;

            foreach (var p in list.EnumerateArray())
            {
                var service = p.GetProperty("service").GetString() ?? "";
                var label = AwsLabel(service);
                if (label is not null && p.TryGetProperty(field, out var cidr))
                    result.Add((cidr.GetString() ?? "", label));
            }
        }

        return result;
    }

    private static IpIntelLabel? AwsLabel(string service) => service switch
    {
        "CLOUDFRONT_ORIGIN_FACING" => new IpIntelLabel("CloudFront", service, IpIntelCategory.Cdn, "aws"),
        "CLOUDFRONT" => new IpIntelLabel("CloudFront", service, IpIntelCategory.Cdn, "aws"),
        "ROUTE53_HEALTHCHECKS" => new IpIntelLabel("Route 53", service, IpIntelCategory.HealthCheck, "aws"),
        _ => null,
    };

    // { "data": { "prefixes": [ { "prefix": "23.193.114.0/24", ... } ] } }
    public static IEnumerable<(string Cidr, IpIntelLabel Label)> ParseRipeStatPrefixes(string body, IpIntelLabel label)
    {
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("data").GetProperty("prefixes").EnumerateArray()
            .Select(p => (p.GetProperty("prefix").GetString() ?? "", label))
            .ToList();
    }

    /// <summary>Keeps only AzureFrontDoor.Backend (what origins see) from the ~5 MB service tags file.</summary>
    public static string ReduceAzureServiceTags(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var backend = doc.RootElement.GetProperty("values").EnumerateArray()
            .First(v => v.GetProperty("name").GetString() == "AzureFrontDoor.Backend");
        var prefixes = backend.GetProperty("properties").GetProperty("addressPrefixes").EnumerateArray()
            .Select(p => p.GetString());
        return string.Join("\n", prefixes);
    }

    public static IEnumerable<(string Cidr, IpIntelLabel Label)> ParseF5(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var services = doc.RootElement.GetProperty("services");
        var label = Cdn("F5 Distributed Cloud", "regional edge", "f5xc");
        var result = new List<(string, IpIntelLabel)>();

        if (services.TryGetProperty("regional_edges", out var edges) && edges.TryGetProperty("regions", out var regions))
            foreach (var region in regions.EnumerateObject())
                result.AddRange(Cidrs(region.Value, label));

        if (services.TryGetProperty("cdn", out var cdn))
            result.AddRange(Cidrs(cdn, label with { Service = "cdn" }));

        return result;
    }

    // { "zscaler.net": { "continent : X": { "city : Y": [ { "range": "a.b.c.d/n", ... } ] } } }
    public static IEnumerable<(string Cidr, IpIntelLabel Label)> ParseZscaler(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var label = new IpIntelLabel("Zscaler", "zscaler.net", IpIntelCategory.CorporateProxy, "zscaler");
        var result = new List<(string, IpIntelLabel)>();
        CollectRanges(doc.RootElement, label, result);
        return result;
    }

    private static void CollectRanges(JsonElement node, IpIntelLabel label, List<(string, IpIntelLabel)> into)
    {
        switch (node.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in node.EnumerateObject())
                {
                    if (prop.NameEquals("range") && prop.Value.ValueKind == JsonValueKind.String)
                        into.Add((prop.Value.GetString() ?? "", label));
                    else
                        CollectRanges(prop.Value, label, into);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in node.EnumerateArray())
                    CollectRanges(item, label, into);
                break;
        }
    }

    private static IEnumerable<(string, IpIntelLabel)> Cidrs(JsonElement obj, IpIntelLabel label)
    {
        foreach (var name in new[] { "ipv4_cidrs", "ipv6_cidrs" })
            if (obj.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var c in arr.EnumerateArray())
                    yield return (c.GetString() ?? "", label);
    }

    public static IEnumerable<(string Cidr, IpIntelLabel Label)> Lines(string body, IpIntelLabel label) =>
        body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('#')[0])
            .SelectMany(line => line.Split(new[] { ' ', '\t', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            .Select(token => (token, label));

    public static IEnumerable<(string Cidr, IpIntelLabel Label)> JsonArrays(string body, IpIntelLabel label, params string[] arrays)
    {
        using var doc = JsonDocument.Parse(body);
        var result = new List<(string, IpIntelLabel)>();
        foreach (var name in arrays)
            if (doc.RootElement.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
                result.AddRange(arr.EnumerateArray().Select(e => (e.GetString() ?? "", label)));
        return result;
    }

    private static IpIntelLabel Cdn(string provider, string service, string feedId) =>
        new(provider, service, IpIntelCategory.Cdn, feedId);

    private static List<(string, IpIntelLabel)> BuildStatic()
    {
        var list = new List<(string, IpIntelLabel)>();
        void Add(IpIntelLabel label, params string[] cidrs) => list.AddRange(cidrs.Select(c => (c, label)));

        // Google Cloud load balancer / CDN to origin (documented static ranges).
        Add(new IpIntelLabel("Google Cloud LB", "proxy-to-origin", IpIntelCategory.Cdn, "static"),
            "130.211.0.0/22", "35.191.0.0/16", "34.96.0.0/20", "34.127.192.0/18");
        // Sucuri WAF.
        Add(new IpIntelLabel("Sucuri", "edge", IpIntelCategory.Cdn, "static"),
            "192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22", "2a02:fe80::/29");
        // Netskope NewEdge egress.
        Add(new IpIntelLabel("Netskope", "NewEdge", IpIntelCategory.CorporateProxy, "static"),
            "163.116.128.0/17", "162.10.0.0/17", "31.186.239.0/24", "8.36.116.0/24", "8.39.144.0/24");
        return list;
    }
}
