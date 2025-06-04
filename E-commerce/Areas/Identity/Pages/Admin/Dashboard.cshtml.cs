using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace E_commerce.Areas.Identity.Pages.Admin
{
    [Authorize(Roles = "Admin")]
    public class DashboardModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;

        public DashboardModel(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public List<UserWithRole> Users { get; set; } = new();

        public class UserWithRole
        {
            public string Email { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
        }

        public async Task OnGetAsync()
        {
            var allUsers = _userManager.Users.ToList();

            foreach (var user in allUsers)
            {
                var roles = await _userManager.GetRolesAsync(user);
                Users.Add(new UserWithRole
                {
                    Email = user.Email ?? "Unknown",
                    Role = roles.FirstOrDefault() ?? "None"
                });
            }
        }
    }
}
