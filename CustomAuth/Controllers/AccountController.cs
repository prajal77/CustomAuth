using CustomAuth.Entities;
using CustomAuth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CustomAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        public AccountController(ApplicationDbContext context)
        {
            _context = context;
        }
        public IActionResult Index()
        {
            return View(_context.UserAccounts.ToList());
        }

        public IActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Registration(Register register)
        {
            if (ModelState.IsValid)
            {
                UserAccount account = new UserAccount();
                account.Email = register.Email;
                account.FirstName = register.FirstName;
                account.LastName = register.LastName;
                account.Password = register.Password;
                account.UserName = register.UserName;
                try
                {
                    _context.UserAccounts.Add(account);
                    _context.SaveChanges();

                    ModelState.Clear();
                    ViewBag.Message = $"{account.FirstName} {account.LastName} registered successfully";
                }
                catch (DbUpdateException)
                {
                    ModelState.AddModelError("", "Please enter unique Email or Password");
                    return View(register);
                }
            }
            return View(register);
        }

        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Login(Login login)
        {
            if (ModelState.IsValid)
            {
                var user = _context.UserAccounts.Where(x => x.Email == login.Email && x.Password == login.Password).FirstOrDefault();
                if (user != null)
                {
                    //Success create cokkie
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Email, login.Email),
                        new Claim("Email",user.Email),
                        new Claim(ClaimTypes.Role, "User"),
                         new Claim(ClaimTypes.Name, user.Email)
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
                    return RedirectToAction("SecurePage");
                }
                else
                {
                    ModelState.AddModelError("", "Email or Password is not correct");
                }
            }
            return View(login);
        }
        [Authorize]
        public IActionResult SecurePage()
        {
            ViewBag.Name = HttpContext.User.Identity.Name;
            return View();
        }
        public IActionResult Logoutt()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index");
        }
     
    }
}
