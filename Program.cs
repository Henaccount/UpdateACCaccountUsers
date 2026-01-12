// Program.cs
// .NET 6+
// Usage example:
//   dotnet run -- \
//     --clientId YOUR_CLIENT_ID \
//     --clientSecret YOUR_CLIENT_SECRET \
//     --accountId YOUR_ACC_ACCOUNT_ID \
//     --csv path/to/users.csv \
//     --region EMEA \
//     --scope "account:read account:write" \
//     --impersonateUserId YOUR_ADMIN_USER_ID
// UpdateACCaccountUsers --clientId xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --clientSecret xxxxxxxxxxxxxxxx --accountId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --csv "C:\Users\theuser\Downloads\users.csv" --region US --scope "account:read account:write" --impersonateUserId xxxxxxxxxxxx

// CSV format (header required):
// email,default company,default role
// alice@contoso.com,Contoso GmbH,Architect
// bob@contoso.com,Contoso GmbH,Contractor
//
// Notes:
// - Uses REST endpoints under /hq/v1/accounts/... (Account Admin API). :contentReference[oaicite:7]{index=7}
// - Token acquired from /authentication/v2/token. :contentReference[oaicite:8]{index=8}
// - For 2-legged write operations, you may need the User-Id header (impersonation). :contentReference[oaicite:9]{index=9}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

public static class Program
{
    private const string BaseUrl = "https://developer.api.autodesk.com";

    public static async Task<int> Main(string[] args)
    {
        var opts = ParseArgs(args);

        if (!opts.TryGetValue("--clientId", out var clientId) ||
            !opts.TryGetValue("--clientSecret", out var clientSecret) ||
            !opts.TryGetValue("--accountId", out var accountId) ||
            !opts.TryGetValue("--csv", out var csvPath))
        {
            Console.Error.WriteLine("Missing required args: --clientId --clientSecret --accountId --csv");
            return 2;
        }

        var region = opts.TryGetValue("--region", out var regionVal) ? regionVal : "US"; // US | EMEA
        var scope = opts.TryGetValue("--scope", out var scopeVal) ? scopeVal : "account:read account:write";
        var impersonateUserId = opts.TryGetValue("--impersonateUserId", out var imp) ? imp : null;

        if (!File.Exists(csvPath))
        {
            Console.Error.WriteLine($"CSV not found: {csvPath}");
            return 2;
        }

        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromMinutes(5);

        // 1) OAuth token
        var token = await Fetch2LeggedTokenAsync(http, clientId, clientSecret, scope);

        // 2) Prepare default headers
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

        // Region header is used by Account Admin endpoints (US/EMEA). :contentReference[oaicite:10]{index=10}
        http.DefaultRequestHeaders.Remove("Region");
        http.DefaultRequestHeaders.Add("Region", region);

        // Optional: User impersonation for 2-legged writes. :contentReference[oaicite:11]{index=11}
        if (!string.IsNullOrWhiteSpace(impersonateUserId))
        {
            http.DefaultRequestHeaders.Remove("User-Id");
            http.DefaultRequestHeaders.Add("User-Id", impersonateUserId);
        }

        // 3) Load lookups
        var companies = await GetAllCompaniesAsync(http, accountId);
        var companyNameToId = companies
            .Where(c => !string.IsNullOrWhiteSpace(c.Name))
            .GroupBy(c => c.Name.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Id, StringComparer.OrdinalIgnoreCase);

        // 4) Load CSV
        var rows = ReadCsv(csvPath);

        // 5) Attempt to build role lookup (name -> id).
        // APS/BIM360 exposes "industry roles" (project roles) via a v2 endpoint per the reference. :contentReference[oaicite:12]{index=12}
        // Unfortunately, the exact URL varies between tenants/products; so this is configurable.
        // If role lookup fails, you can put the role ID directly in the CSV (the script will detect GUIDs),
        // or set --roleLookupUrl to a working endpoint returning a list of roles.
        var roleNameToId = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (opts.TryGetValue("--roleLookupUrl", out var roleLookupUrl) && !string.IsNullOrWhiteSpace(roleLookupUrl))
        {
            try
            {
                var roles = await GetRolesFromCustomEndpointAsync(http, roleLookupUrl);
                roleNameToId = roles
                    .Where(r => !string.IsNullOrWhiteSpace(r.Name) && !string.IsNullOrWhiteSpace(r.Id))
                    .GroupBy(r => r.Name.Trim(), StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.First().Id, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARN] Role lookup failed ({ex.Message}). Will only accept role IDs in CSV or skip role updates.");
            }
        }
        else
        {
            Console.WriteLine("[INFO] No --roleLookupUrl provided. Role names in CSV will NOT be resolved automatically.");
            Console.WriteLine("       Provide role IDs in CSV, or pass --roleLookupUrl <endpoint> that returns roles as [{id,name},...].");
        }

        // 6) Process each row
        var ok = 0;
        var fail = 0;

        foreach (var row in rows)
        {
            Console.WriteLine($"--- {row.Email} ---");

            try
            {
                // Resolve user by email: /hq/v1/accounts/{account_id}/users/search :contentReference[oaicite:13]{index=13}
                var user = await FindUserByEmailAsync(http, accountId, row.Email);
                if (user == null)
                {
                    Console.WriteLine($"[FAIL] User not found for email: {row.Email}");
                    fail++;
                    continue;
                }

                // Resolve company
                string? companyId = null;
                if (!string.IsNullOrWhiteSpace(row.DefaultCompany))
                {
                    var key = row.DefaultCompany.Trim();
                    if (!companyNameToId.TryGetValue(key, out var cid))
                    {
                        Console.WriteLine($"[FAIL] Company name not found in account directory: '{row.DefaultCompany}'");
                        fail++;
                        continue;
                    }
                    companyId = cid;
                }

                // Resolve role
                string? defaultRoleId = null;
                if (!string.IsNullOrWhiteSpace(row.DefaultRole))
                {
                    var roleTrim = row.DefaultRole.Trim();
                    //mb: role is expected 
                    defaultRoleId = roleTrim;
                    /*if (LooksLikeGuid(roleTrim))
                    {
                        defaultRoleId = roleTrim;
                    }
                    else if (roleNameToId.TryGetValue(roleTrim, out var rid))
                    {
                        defaultRoleId = rid;
                    }
                    else
                    {
                        Console.WriteLine($"[WARN] Could not resolve role '{row.DefaultRole}'. " +
                                          $"Either provide role ID in CSV, or use --roleLookupUrl.");
                        // Keep going: we can still update company_id even if role is unknown.
                    }*/
                }

                // PATCH user: /hq/v1/accounts/{account_id}/users/{user_id} :contentReference[oaicite:14]{index=14}
                // The reference describes status/default company; real payloads also include default_role_id. :contentReference[oaicite:15]{index=15}
                var patch = new Dictionary<string, object?>();
                if (!string.IsNullOrWhiteSpace(companyId)) patch["company_id"] = companyId;
                if (!string.IsNullOrWhiteSpace(defaultRoleId)) patch["default_role"] = defaultRoleId;

                if (patch.Count == 0)
                {
                    Console.WriteLine("[SKIP] Nothing to update (no company/role).");
                    ok++;
                    continue;
                }

                await PatchAccountUserAsync(http, accountId, user.Id!, patch);

                Console.WriteLine($"[OK] Updated userId={user.Id} company_id={companyId ?? "(unchanged)"} default_role={defaultRoleId ?? "(unchanged)"}");
                ok++;
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"[FAIL] HTTP error: {ex.Message}");
                fail++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] Unexpected error: {ex}");
                fail++;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Done. OK={ok}, FAIL={fail}");
        return fail == 0 ? 0 : 1;
    }

    // -----------------------------
    // REST calls
    // -----------------------------

    private static async Task<TokenResponse> Fetch2LeggedTokenAsync(HttpClient http, string clientId, string clientSecret, string scope)
    {
        // POST /authentication/v2/token :contentReference[oaicite:16]{index=16}
        var url = $"{BaseUrl}/authentication/v2/token";
        using var req = new HttpRequestMessage(HttpMethod.Post, url);

        // Basic auth with client_id:client_secret
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);

        req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = scope
        });

        using var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Token request failed: {(int)resp.StatusCode} {resp.ReasonPhrase} - {body}");

        var token = JsonSerializer.Deserialize<TokenResponse>(body, JsonOpts())!;
        if (string.IsNullOrWhiteSpace(token.AccessToken))
            throw new Exception("Token response missing access_token.");

        return token;
    }

    private static async Task<List<Company>> GetAllCompaniesAsync(HttpClient http, string accountId)
    {
        // GET /hq/v1/accounts/{account_id}/companies :contentReference[oaicite:17]{index=17}
        var results = new List<Company>();
        int offset = 0;
        const int limit = 100;

        while (true)
        {
            var url = $"{BaseUrl}/hq/v1/accounts/{Uri.EscapeDataString(accountId)}/companies?limit={limit}&offset={offset}";
            using var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"Get companies failed: {(int)resp.StatusCode} {resp.ReasonPhrase} - {body}");

            var page = JsonSerializer.Deserialize<List<Company>>(body, JsonOpts()) ?? new List<Company>();
            results.AddRange(page);

            if (page.Count < limit) break;
            offset += limit;
        }

        return results;
    }

    private static async Task<User?> FindUserByEmailAsync(HttpClient http, string accountId, string email)
    {
        // GET /hq/v1/accounts/{account_id}/users/search :contentReference[oaicite:18]{index=18}
        // The search endpoint supports searching by specified fields; email is commonly supported.
        var url = $"{BaseUrl}/hq/v1/accounts/{Uri.EscapeDataString(accountId)}/users/search?email={Uri.EscapeDataString(email)}";
        using var resp = await http.GetAsync(url);
        var body = await resp.Content.ReadAsStringAsync();

        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"User search failed: {(int)resp.StatusCode} {resp.ReasonPhrase} - {body}");

        // Search endpoints often return an array
        var users = JsonSerializer.Deserialize<List<User>>(body, JsonOpts());
        return users?.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task PatchAccountUserAsync(HttpClient http, string accountId, string userId, Dictionary<string, object?> patch)
    {
        // PATCH /hq/v1/accounts/{account_id}/users/{user_id} 
        var url = $"{BaseUrl}/hq/v1/accounts/{Uri.EscapeDataString(accountId)}/users/{Uri.EscapeDataString(userId)}";
        using var req = new HttpRequestMessage(HttpMethod.Patch, url);

        var json = JsonSerializer.Serialize(patch, JsonOpts());
        req.Content = new StringContent(json, Encoding.UTF8, "application/json");

        using var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"PATCH user failed: {(int)resp.StatusCode} {resp.ReasonPhrase} - {body}");
    }

    private static async Task<List<SimpleRole>> GetRolesFromCustomEndpointAsync(HttpClient http, string roleLookupUrl)
    {
        // Caller supplies an endpoint that returns something like:
        //   [{ "id":"...", "name":"..." }, ...]
        // or:
        //   { "data":[{id,name},...] }
        using var resp = await http.GetAsync(roleLookupUrl);
        var body = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Role lookup failed: {(int)resp.StatusCode} {resp.ReasonPhrase} - {body}");

        // Try array first
        var arr = JsonSerializer.Deserialize<List<SimpleRole>>(body, JsonOpts());
        if (arr != null) return arr;

        // Try wrapper { data: [...] }
        var wrapper = JsonSerializer.Deserialize<RoleWrapper>(body, JsonOpts());
        return wrapper?.Data ?? new List<SimpleRole>();
    }

    // -----------------------------
    // CSV + models
    // -----------------------------

    private static List<CsvRow> ReadCsv(string path)
    {
        var lines = File.ReadAllLines(path);

        if (lines.Length == 0) return new List<CsvRow>();
        var header = SplitCsvLine(lines[0]).Select(h => h.Trim().Trim('"')).ToList();

        int idxEmail = header.FindIndex(h => h.Equals("email", StringComparison.OrdinalIgnoreCase));
        int idxCompany = header.FindIndex(h => h.Equals("default company", StringComparison.OrdinalIgnoreCase));
        int idxRole = header.FindIndex(h => h.Equals("default role", StringComparison.OrdinalIgnoreCase));

        if (idxEmail < 0) throw new Exception("CSV header must include 'email' column.");

        var rows = new List<CsvRow>();
        for (int i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i])) continue;
            var cols = SplitCsvLine(lines[i]);

            string email = Get(cols, idxEmail);
            string company = idxCompany >= 0 ? Get(cols, idxCompany) : "";
            string role = idxRole >= 0 ? Get(cols, idxRole) : "";

            if (string.IsNullOrWhiteSpace(email)) continue;

            rows.Add(new CsvRow(email.Trim(), company.Trim(), role.Trim()));
        }
        return rows;

        static string Get(List<string> cols, int idx) => (idx >= 0 && idx < cols.Count) ? cols[idx].Trim().Trim('"') : "";
    }

    // Minimal CSV parser supporting commas and quotes.
    private static List<string> SplitCsvLine(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            var c = line[i];

            if (c == '"')
            {
                // toggle unless escaped double quote
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }

        result.Add(sb.ToString());
        return result;
    }

    private static bool LooksLikeGuid(string s) => Guid.TryParse(s, out _);

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) continue;
            var key = args[i];
            var val = (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                ? args[++i]
                : "true";
            dict[key] = val;
        }
        return dict;
    }

    private static JsonSerializerOptions JsonOpts() => new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    // -----------------------------
    // DTOs
    // -----------------------------

    public record CsvRow(string Email, string DefaultCompany, string DefaultRole);

    public sealed class TokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("token_type")] public string? TokenType { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }

    public sealed class Company
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
    }

    public sealed class User
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("email")] public string? Email { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }

        // commonly seen in payloads/responses: default_role_id, company_id, etc. 
        [JsonPropertyName("company_id")] public string? CompanyId { get; set; }
        [JsonPropertyName("default_role")] public string? DefaultRoleId { get; set; }
    }

    public sealed class SimpleRole
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
    }

    public sealed class RoleWrapper
    {
        [JsonPropertyName("data")] public List<SimpleRole>? Data { get; set; }
    }
}

