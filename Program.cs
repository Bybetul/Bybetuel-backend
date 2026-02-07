using System.Text;
using backend;
using backend.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ============================
// Controllers + Swagger
// ============================
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ============================
// Database (SQLite)
// ============================
builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default"))
);

// ============================
// Password Hasher
// ============================
builder.Services.AddScoped<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();

// ============================
// JWT Settings
// ============================
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var jwtKey = builder.Configuration["Jwt:Key"];

if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
    throw new Exception("Jwt:Key muss mindestens 32 Zeichen lang sein!");

var jwtKeyBytes = Encoding.UTF8.GetBytes(jwtKey);

// ============================
// Auth
// ============================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),
            ClockSkew = TimeSpan.Zero
        };

        // ✅ Token aus Header ODER Cookie holen
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                // 1) Authorization Header
                var authHeader = ctx.Request.Headers["Authorization"].ToString();
                if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer "))
                {
                    var token = authHeader["Bearer ".Length..].Trim();
                    if (!string.IsNullOrWhiteSpace(token) && token != "undefined" && token != "null")
                    {
                        ctx.Token = token;
                        return Task.CompletedTask;
                    }
                }

                // 2) Cookie fallback
                if (ctx.Request.Cookies.TryGetValue("access_token", out var cookieToken))
                {
                    if (!string.IsNullOrWhiteSpace(cookieToken))
                        ctx.Token = cookieToken;
                }

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                Console.WriteLine("JWT FAILED: " + ctx.Exception.Message);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// ============================
// CORS (Frontend darf API + Cookies)
// ============================
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("AllowFrontend", policy =>
    {
        policy
            .WithOrigins(
                "http://localhost:3000",
                "http://localhost:5173",
                "https://bybetuel.de",
                "https://www.bybetuel.de"
            )
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

var app = builder.Build();

// ============================
// ✅ RAILWAY PORT FIX (WICHTIG)
// ============================
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
app.Urls.Clear();
app.Urls.Add($"http://0.0.0.0:{port}");

// ============================
// ✅ DB + Admin Seed (BLEIBT)
// ============================
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<AppUser>>();
    var adminEmail = builder.Configuration["Admin:Email"];
    var adminPassword = builder.Configuration["Admin:Password"];

    if (!string.IsNullOrWhiteSpace(adminEmail) && !string.IsNullOrWhiteSpace(adminPassword))
    {
        if (!db.Users.Any(u => u.Email == adminEmail))
        {
            var admin = new AppUser
            {
                Email = adminEmail,
                IsAdmin = true
            };

            admin.PasswordHash = hasher.HashPassword(admin, adminPassword);
            db.Users.Add(admin);
            db.SaveChanges();

            Console.WriteLine($"✅ Admin seeded: {adminEmail}");
        }
    }
}

// ============================
// ✅ Swagger IMMER (auch online)
// ============================
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1");
    c.RoutePrefix = "swagger"; // URL: /swagger
});

// ============================
// Middleware Reihenfolge (WICHTIG)
// ============================
app.UseCors("AllowFrontend");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
