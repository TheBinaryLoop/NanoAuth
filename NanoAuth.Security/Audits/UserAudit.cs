using System;

namespace NanoAuth.Security.Audits
{
    public class UserAudit
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTimeOffset Timestamp { get; set; } = DateTime.UtcNow;
        public string IpAddress { get; set; }
        public UserAuditEventType AuditEvent { get; set; }
    }
}