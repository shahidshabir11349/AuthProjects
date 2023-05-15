using AuthManual.Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthManual.Controllers
{
    public class AccountController : Controller
    {
        //public IActionResult Index()
        //{
        //    return View();
        //}

        [HttpGet] // Display all the properties the user has to enter
        public async Task<IActionResult> Register()
        {
            var registerViewModel = new RegisterViewModel();
            return View(registerViewModel);
        }
    }
}
