using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.AspNetCore.Tests.Utils;
using System.Net;
using System.Text;

namespace ModelContextProtocol.AspNetCore.Tests;

/// <summary>
/// Tests for DNS rebinding protection via Origin header validation.
///
/// The MCP spec (2025-06-18) requires:
///   "Servers MUST validate the Origin header on all incoming connections
///    to prevent DNS rebinding attacks."
///
/// Decision table for <see cref="HttpServerTransportOptions.AllowedOrigins"/>:
///
///   AllowedOrigins | Origin header      | Result
///   ---------------|--------------------|--------
///   null (default) | any / absent       | 200 OK  (opt-in only, no breaking change)
///   configured     | absent             | 200 OK  (non-browser clients never send Origin)
///   configured     | in allowlist       | 200 OK
///   configured     | NOT in allowlist   | 403 Forbidden  ← DNS rebinding blocked
///   configured     | "null" (opaque)    | 403 Forbidden  ← sandboxed iframe blocked
/// </summary>
public class OriginValidationTests(ITestOutputHelper outputHelper) : KestrelInMemoryTest(outputHelper), IAsyncDisposable
{
    private WebApplication? _app;

    private const string InitializePayload = """
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
          "protocolVersion":"2025-03-26",
          "capabilities":{},
          "clientInfo":{"name":"test","version":"1"}
        }}
        """;

    private async Task StartServerAsync(IList<string>? allowedOrigins = null)
    {
        Builder.Services
            .AddMcpServer()
            .WithHttpTransport(options =>
            {
                options.AllowedOrigins = allowedOrigins;
            });

        _app = Builder.Build();
        _app.MapMcp();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        HttpClient.DefaultRequestHeaders.Add("Accept", "application/json, text/event-stream");
        HttpClient.DefaultRequestHeaders.Add("MCP-Protocol-Version", "2025-03-26");
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
        base.Dispose();
    }

    private Task<HttpResponseMessage> PostMcpAsync(string? origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5000/");
        request.Content = new StringContent(InitializePayload, Encoding.UTF8, "application/json");
        if (origin is not null)
            request.Headers.TryAddWithoutValidation("Origin", origin);
        return HttpClient.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private Task<HttpResponseMessage> GetMcpAsync(string? origin, string sessionId)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/");
        request.Headers.Add("Mcp-Session-Id", sessionId);
        if (origin is not null)
            request.Headers.TryAddWithoutValidation("Origin", origin);
        return HttpClient.SendAsync(request, TestContext.Current.CancellationToken);
    }

    // ── AllowedOrigins = null (default) ───────────────────────────────────────

    [Fact]
    public async Task AllowedOrigins_Null_AcceptsRequestWithNoOrigin()
    {
        await StartServerAsync(allowedOrigins: null);

        using var response = await PostMcpAsync(origin: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Null_AcceptsRequestWithEvilOrigin()
    {
        // When AllowedOrigins is null the feature is disabled entirely — no breaking change.
        await StartServerAsync(allowedOrigins: null);

        using var response = await PostMcpAsync(origin: "http://evil.attacker.com");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── AllowedOrigins configured — absent Origin ─────────────────────────────

    [Fact]
    public async Task AllowedOrigins_Configured_AcceptsRequestWithNoOrigin()
    {
        // Non-browser clients (SDKs, curl) never send Origin — must not be blocked.
        await StartServerAsync(allowedOrigins: ["http://localhost", "http://127.0.0.1"]);

        using var response = await PostMcpAsync(origin: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── AllowedOrigins configured — allowed Origins ───────────────────────────

    [Fact]
    public async Task AllowedOrigins_Configured_AcceptsRequestWithAllowedOrigin()
    {
        await StartServerAsync(allowedOrigins: ["http://localhost", "http://127.0.0.1"]);

        using var response = await PostMcpAsync(origin: "http://localhost");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_AcceptsMultipleAllowedOrigins()
    {
        await StartServerAsync(allowedOrigins: ["http://localhost", "https://localhost", "http://127.0.0.1"]);

        using var r1 = await PostMcpAsync(origin: "http://localhost");
        using var r2 = await PostMcpAsync(origin: "http://127.0.0.1");

        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
    }

    // ── AllowedOrigins configured — blocked Origins ───────────────────────────

    [Fact]
    public async Task AllowedOrigins_Configured_BlocksEvilOrigin()
    {
        // Core DNS rebinding scenario: browser sends Origin: http://evil.attacker.com
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var response = await PostMcpAsync(origin: "http://evil.attacker.com");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_BlocksNullOpaqueOrigin()
    {
        // Sandboxed iframes and local file:// pages send Origin: null
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var response = await PostMcpAsync(origin: "null");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_BlocksOriginWithDifferentPort()
    {
        // Origin matching must be exact — different port is a different origin.
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var response = await PostMcpAsync(origin: "http://localhost:8080");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_BlocksOriginWithDifferentScheme()
    {
        // http vs https are different origins.
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var response = await PostMcpAsync(origin: "https://localhost");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_ForbiddenResponseIsJsonRpcError()
    {
        // The 403 response body should be a JSON-RPC error object so clients can parse it.
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var response = await PostMcpAsync(origin: "http://evil.attacker.com");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("error", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("evil.attacker.com", body);
    }

    // ── GET endpoint ──────────────────────────────────────────────────────────

    [Fact]
    public async Task AllowedOrigins_Configured_BlocksEvilOriginOnGetRequest()
    {
        // The GET SSE stream must also be protected — same Origin check.
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        // First establish a session via POST (no origin, non-browser style)
        using var initResponse = await PostMcpAsync(origin: null);
        Assert.Equal(HttpStatusCode.OK, initResponse.StatusCode);
        var sessionId = initResponse.Headers.TryGetValues("Mcp-Session-Id", out var vals)
            ? vals.First() : string.Empty;

        // Now try GET with evil origin
        using var getResponse = await GetMcpAsync(origin: "http://evil.attacker.com", sessionId);

        Assert.Equal(HttpStatusCode.Forbidden, getResponse.StatusCode);
    }

    [Fact]
    public async Task AllowedOrigins_Configured_AllowsGetRequestWithNoOrigin()
    {
        await StartServerAsync(allowedOrigins: ["http://localhost"]);

        using var initResponse = await PostMcpAsync(origin: null);
        Assert.Equal(HttpStatusCode.OK, initResponse.StatusCode);
        var sessionId = initResponse.Headers.TryGetValues("Mcp-Session-Id", out var vals)
            ? vals.First() : string.Empty;

        // GET with no Origin (SDK client) — should be allowed
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            using var getResponse = await GetMcpAsync(origin: null, sessionId);
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        }
        catch (OperationCanceledException)
        {
            // SSE stream stayed open — that means it was accepted (200), not rejected (403).
            // A 403 would have completed immediately without needing cancellation.
        }
    }
}
