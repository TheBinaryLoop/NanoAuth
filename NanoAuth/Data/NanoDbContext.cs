using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Extensions;
using IdentityServer4.EntityFramework.Interfaces;
using IdentityServer4.EntityFramework.Options;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NanoAuth.Data.Identity;
using System;
using System.Threading.Tasks;
using NanoAuth.Data.Audits;

namespace NanoAuth.Data
{
    public class NanoDbContext : IdentityDbContext<NanoUser, NanoRole, string>, IPersistedGrantDbContext
    {
        private readonly OperationalStoreOptions _storeOptions;

        public DbSet<UserAuditEvent> UserAuditEvents { get; set; }
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

                b.HasMany(x => x.AuditEvents).WithOne(a => a.User).IsRequired();
            });

            builder.Entity<UserAuditEvent>(b =>
            {
                b.ToTable("UserAuditEvent");

                b.HasKey(x => x.Id);

                b.Property(x => x.AuditEvent).IsRequired();
                b.Property(x => x.Timestamp).IsRequired();
                b.Property(x => x.IpAddress).IsRequired();
            });
        }
    }
}