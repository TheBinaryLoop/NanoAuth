using Microsoft.AspNetCore.Identity;

namespace NanoAuth.Data.Identity
{
    public class NanoRole : IdentityRole
    {
        public NanoRole() { }

        public NanoRole(string roleName) : base(roleName) { }
    }
}