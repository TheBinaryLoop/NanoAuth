using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using NanoAuth.Data.Audits;

namespace NanoAuth.Data.Identity
{
    public class NanoUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public virtual IEnumerable<UserAuditEvent> AuditEvents { get; set; }
    }
}