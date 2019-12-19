using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Extensions;
using IdentityServer4.EntityFramework.Interfaces;
using IdentityServer4.EntityFramework.Options;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NanoAuth.Data.Identity;
using System;
using System.Threading.Tasks;

namespace NanoAuth.Data
{
    public class NanoDbContext : IdentityDbContext<NanoUser, NanoRole, string>, IPersistedGrantDbContext
    {
        private readonly OperationalStoreOptions _storeOptions;

        public DbSet<PersistedGrant> PersistedGrants { get; set; }
        public DbSet<DeviceFlowCodes> DeviceFlowCodes { get; set; }

        public NanoDbContext(DbContextOptions<NanoDbContext> options, OperationalStoreOptions storeOptions)
            : base(options)
        {
            _storeOptions = storeOptions ?? throw new ArgumentNullException(nameof(storeOptions));
        }

        public Task<int> SaveChangesAsync()
        {
            return base.SaveChangesAsync();
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.ConfigurePersistedGrantContext(_storeOptions);
            base.OnModelCreating(builder);

            builder.Entity<NanoUser>(b =>
            {
                b.Property(u => u.FirstName).HasMaxLength(100).IsRequired();
                b.Property(u => u.LastName).HasMaxLength(100).IsRequired();
            });
        }
    }
}