using CRUD_Angular_16.Models;
using Microsoft.EntityFrameworkCore;

namespace CRUD_Angular_16.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options) { }

        public DbSet<User> Users { get; set; } 
    }
  
}
