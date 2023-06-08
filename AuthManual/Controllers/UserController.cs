using AuthManual.Data;
using AuthManual.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace AuthManual.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            var userLisT = _db.ApplicationUser.ToList();
            var userRoles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userLisT)
            {
                var role = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId)!.Name;
                } 
            }

            return View(userLisT);
        }

        [HttpGet]
        public IActionResult Edit(string userId)
        {
            var dbUser = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (dbUser == null)
            {
                return NotFound();
            }

            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userRole.FirstOrDefault(u => u.UserId == dbUser.Id);
            if (role != null)
            {
                dbUser.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId)!.Id;
            }

            dbUser.RoleList = _db.Roles.Select(u => new SelectListItem
            {
                Text = u.Name,
                Value = u.Id,
            });

            return View(dbUser);
        }

        [HttpPost]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (ModelState.IsValid)
            {
                var dbUser = _db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
                if (dbUser == null)
                {
                    return NotFound();
                }

                var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == dbUser.Id);
                if (userRole != null) // user already has a role
                {
                    var previousRoleName = _db.Roles
                        .Where(u => u.Id == userRole.RoleId)
                        .Select(e => e.Name)
                        .FirstOrDefault();
                    // Removing old role from user
                    await _userManager.RemoveFromRoleAsync(dbUser, previousRoleName);
                }

                // Adding new role
                await _userManager.AddToRoleAsync(dbUser, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId)!.Name);

                // Updating the name
                dbUser.Name = user.Name;

                await _db.SaveChangesAsync();

                TempData["success"] = "User Edited Successfully.";

                return RedirectToAction("Index", "User");
            }

            user.RoleList = _db.Roles.Select(u => new SelectListItem
            {
                Text = u.Name,
                Value = u.Id,
            });

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LockUnlock(string userId)
        {
            var dbUser = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (dbUser == null)
            {
                return NotFound();
            }

            if (dbUser.LockoutEnd != null && dbUser.LockoutEnd > DateTime.Now)
            {
                // User is locked and we have to unlock
                dbUser.LockoutEnd = DateTime.Now;
                TempData["success"] = "User unlocked successfully";
            }
            else
            {
                // User is not locked 
                dbUser.LockoutEnd = DateTimeOffset.Now.AddYears(50);
                TempData["success"] = "User locked successfully";
            }

            _db.SaveChanges();

            return RedirectToAction("Index", "User");
        }

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var dbUser = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (dbUser == null)
            {
                return NotFound();
            }

            _db.ApplicationUser.Remove(dbUser);
            _db.SaveChanges();
            TempData["success"] = "User deleted successfully.";
            return RedirectToAction("Index", "User");
        }
    }
}
