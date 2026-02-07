using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;

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

    [HttpPost("login")]
    public IActionResult Login(LoginDto dto)
    {
        var email = dto.Email.Trim().ToLower();
        var user = _db.Users.FirstOrDefault(u => u.Email.ToLower() == email);
        if (user == null) return Unauthorized();

        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, dto.Password);
        if (result == PasswordVerificationResult.Failed)
            return Unauthorized();

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_cfg["Jwt:Key"]!)
        );

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("isAdmin", user.IsAdmin ? "true" : "false")
        };

        var token = new JwtSecurityToken(
            issuer: _cfg["Jwt:Issuer"],
            audience: _cfg["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        Response.Cookies.Append("access_token", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure = false, // lokal false
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = DateTimeOffset.UtcNow.AddHours(12)
        });

        return Ok(new { ok = true });
    }

    [Authorize]
    [HttpGet("me")]
    public IActionResult Me()
    {
        return Ok(new
        {
            email = User.FindFirstValue(JwtRegisteredClaimNames.Email),
            isAdmin = User.FindFirstValue("isAdmin") == "true"
        });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("access_token", new CookieOptions
        {
            Path = "/",
            SameSite = SameSiteMode.Lax
        });

        return Ok();
    }
}
