using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace DatingApp.API.Models
{
    public class Role : IdentityRole<int>
    {
        public ICollection<User> UserRoles { get; set; }
    }
}