using Authentication_Playground_.Models;
using Microsoft.EntityFrameworkCore;

namespace Authentication_Playground_.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }

        public DbSet<Users> Users { get; set; }
    }
}
