using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace backend.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _cfg;
    private readonly IPasswordHasher<AppUser> _hasher;

    public AuthController(
        AppDbContext db,
        IConfiguration cfg,
        IPasswordHasher<AppUser> hasher)
    {
        _db = db;
        _cfg = cfg;
        _hasher = hasher;
    }

    public record LoginDto(string Email, string Password);

    // POST /api/auth/login
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginDto dto)
    {
        if (dto is null) return BadRequest();

        var email = (dto.Email ?? "").Trim().ToLower();
        var password = dto.Password ?? "";

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return Unauthorized();

        var user = _db.Users.FirstOrDefault(u => u.Email.ToLower() == email);
        if (user == null) return Unauthorized();

        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed)
            return Unauthorized();

        // ================= JWT =================
        var jwtKey = _cfg["Jwt:Key"] ?? "";
        if (jwtKey.Length < 32)
            return StatusCode(500, "JWT Key must be at least 32 characters.");

        var issuer = _cfg["Jwt:Issuer"];
        var audience = _cfg["Jwt:Audience"];

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new("isAdmin", user.IsAdmin ? "true" : "false")
        };

        if (user.IsAdmin)
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12),
            signingCredentials: creds
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        // ================= COOKIE =================
        var isProd = string.Equals(
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            "Production",
            StringComparison.OrdinalIgnoreCase
        );

        Response.Cookies.Append("access_token", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure = isProd,
            SameSite = isProd ? SameSiteMode.None : SameSiteMode.Lax,
            Path = "/",
            Expires = DateTimeOffset.UtcNow.AddHours(12)
        });

        return Ok(new
        {
            ok = true,
            token = jwt,
            isAdmin = user.IsAdmin,
            email = user.Email
        });
    }

    // GET /api/auth/me
    [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        var email =
            User.FindFirstValue(JwtRegisteredClaimNames.Email) ??
            User.FindFirstValue(ClaimTypes.Email);

        var isAdmin = (User.FindFirstValue("isAdmin") ?? "false") == "true";

        return Ok(new { email, isAdmin });
    }

    // POST /api/auth/logout
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        var isProd = string.Equals(
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            "Production",
            StringComparison.OrdinalIgnoreCase
        );

        Response.Cookies.Delete("access_token", new CookieOptions
        {
            Path = "/",
            Secure = isProd,
            SameSite = isProd ? SameSiteMode.None : SameSiteMode.Lax
        });

        return Ok(new { ok = true });
    }
}
