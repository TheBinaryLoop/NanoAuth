using Microsoft.AspNetCore.Identity;

namespace NanoAuth.Data.Identity
{
    public class NanoUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}