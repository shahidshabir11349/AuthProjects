using System.Text.Encodings.Web;
using AuthManual.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthManual.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UrlEncoder _urlEncoder;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _urlEncoder = urlEncoder;
        }


        //public IActionResult Index()
        //{
        //    return View();
        //}

        [HttpGet] // Display all the properties the user has to enter
        public async Task<IActionResult> Register(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var registerViewModel = new RegisterViewModel();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Redirect(returnUrl);
            }
            else
            {
                AddErrors(result);
            }

            return View(model);
        }

        [HttpGet] // Display all the properties the user has to enter
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,
                lockoutOnFailure: true);
            if (result.Succeeded)
            {
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction("VerifyAuthenticatorCode", new { returnUrl, model.RememberMe });
                }
                return Redirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("LockedOut");
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("index", "Home");
        }

        // Forget Password
        [HttpGet] // Display all the properties the user has to enter
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
            // Configure and send a token
        {
            if (ModelState.IsValid)
            {
                // Checking if user exists
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return Content("User Not found.");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new { code = code, userId = user.Id },
                    protocol: HttpContext.Request.Scheme);

                return View("ForgotPasswordConfirmation", new ResetPasswordLinkViewModel{Link = callbackurl!});
            }

            return View(model);
        }

        // Reset password

        [HttpGet] // Display all the properties the user has to enter
        public IActionResult ResetPassword(string? code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
            // Configure and send a token
        {
            if (ModelState.IsValid)
            {
                // Checking if user exists
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return Content("User Not found.");
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                if (result.Succeeded)
                {
                    return View("ResetPasswordConfirmation");
                }
                AddErrors(result );
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator() 
            // the method will be used anytime the user wants to enable authentication
        {
            string AuthenticationUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            // this will find the user that is logged in
            var user = await _userManager.GetUserAsync(User);

            // If there are any previous authenticators we will reset those
            await _userManager.ResetAuthenticatorKeyAsync(user);

            // Generating a new token
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthenticatorUri = string.Format(AuthenticationUriFormat, _urlEncoder.Encode("ManualAuth"),
                _urlEncoder.Encode(user.Email), token);

            var model = new TwoFactorAuthenticationViewModel { Token = token , QRCodeUrl = AuthenticatorUri};
            return View(model);

        }

        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user,
                    _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code could not be validated.");
                    return View(model);
                }
            }
            return View("AuthenticationConfirmation");
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnurl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnurl, RememberMe = rememberMe });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            model.ReturnUrl ??= Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient:false);

            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("LockedOut");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid Code.");
                return View(model);
            }

        }

        private void AddErrors(IdentityResult result) // Helper method 
        {
            foreach (var err in result.Errors)
            {
                ModelState.AddModelError(string.Empty, err.Description);
            }
        }
    }
}