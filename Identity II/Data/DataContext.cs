using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Identity_II.Data;

public class DataContext : IdentityDbContext
{
    public DataContext(DbContextOptions<DataContext> options): base(options)
    { }
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        SeedRoles(builder);
    }

    private static void SeedRoles(ModelBuilder builder){
        builder.Entity<IdentityRole>().HasData(
            new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName ="ADMIN"},
            new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName ="USER"},
            new IdentityRole() { Name = "HR", ConcurrencyStamp = "3", NormalizedName ="RRHH"}
        );
    }
}
