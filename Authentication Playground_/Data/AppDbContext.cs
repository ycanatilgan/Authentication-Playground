using Microsoft.EntityFrameworkCore;

namespace Authentication_Playground_.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
        {

        }
    }
}
