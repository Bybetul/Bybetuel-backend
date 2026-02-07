using System.Text;
using backend;
using backend.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

//
// =========================
// Controllers
// =========================
builder.Services.AddControllers();

//
// =========================
// Database (SQLite)
// =========================
builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default"))
);

//
// =========================
// Password Hasher
// =========================
builder.Services.AddScoped<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();

//
// =========================
// JWT CONFIG
// =========================
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var jwtKey = builder.Configuration["Jwt:Key"];

if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
    throw new Exception("Jwt:Key muss mindestens 32 Zeichen lang sein");

var jwtKeyBytes = Encoding.UTF8.GetBytes(jwtKey);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),
            ClockSkew = TimeSpan.Zero
        };

        opt.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
                if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer "))
                {
                    ctx.Token = auth.Substring("Bearer ".Length);
                }

                if (ctx.Request.Cookies.TryGetValue("access_token", out var cookie))
                {
                    ctx.Token = cookie;
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

//
// =========================
// CORS
// =========================
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("AllowFrontend", p =>
    {
        p.WithOrigins(
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

//
// =========================
// 🔥 SWAGGER MIT JWT (DAS FEHLTE)
// =========================
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "backend",
        Version = "v1"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization Header: Bearer {token}"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

//
// =========================
// BUILD
// =========================
var app = builder.Build();

//
// =========================
// RAILWAY PORT FIX
// =========================
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
app.Urls.Clear();
app.Urls.Add($"http://0.0.0.0:{port}");

//
// =========================
// DB + ADMIN SEED
// =========================
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<AppUser>>();
    var adminEmail = builder.Configuration["Admin:Email"];
    var adminPassword = builder.Configuration["Admin:Password"];

    if (!string.IsNullOrWhiteSpace(adminEmail) &&
        !string.IsNullOrWhiteSpace(adminPassword) &&
        !db.Users.Any(u => u.Email == adminEmail))
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

//
// =========================
// MIDDLEWARE
// =========================
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1");
    c.RoutePrefix = "swagger";
});

app.UseCors("AllowFrontend");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
