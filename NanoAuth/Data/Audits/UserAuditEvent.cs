using System;
using NanoAuth.Data.Identity;

namespace NanoAuth.Data.Audits
{
    public class UserAuditEvent
    {
        public int Id { get; set; }
        public DateTimeOffset Timestamp { get; set; } = DateTime.UtcNow;
        public string IpAddress { get; set; }
        public UserAuditEventType AuditEvent { get; set; }

        public virtual NanoUser User { get; set; }
    }
}