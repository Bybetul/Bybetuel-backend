using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }

        public DbSet<AppUser> Users => Set<AppUser>();
        public DbSet<Order> Orders => Set<Order>();
    }
}
