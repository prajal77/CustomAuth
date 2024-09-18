using CustomAuth.Entities;
using CustomAuth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CustomAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _config;
        public AccountController(ApplicationDbContext context,IConfiguration config)
        {
            _context = context;
            _config = config;
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
                var passwordHasher = new PasswordHasher<UserAccount>();
                UserAccount account = new UserAccount();
                account.Email = register.Email;
                account.FirstName = register.FirstName;
                account.LastName = register.LastName;
                //account.Password = register.Password;
                account.UserName = register.UserName;
                //hash the password
                account.Password= passwordHasher.HashPassword(account,register.Password);
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
                var user = _context.UserAccounts.Where(x => x.Email == login.Email).FirstOrDefault();
                if (user != null)
                {
                    var passwordHasher = new PasswordHasher<UserAccount>();
                    var result = passwordHasher.VerifyHashedPassword(user, user.Password,login.Password);
                    
                    if(result == PasswordVerificationResult.Success)
                    {
                        //Success create cokkie
                        var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Email, login.Email),
                        new Claim("Email",user.Email),
                        new Claim(ClaimTypes.Role, "User"),
                         new Claim(ClaimTypes.Name, user.Email)
                    };
                        // Generate JWT token
                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var token = new JwtSecurityToken(
                            issuer: _config["Jwt:Issuer"],
                            audience: _config["Jwt:Audience"],
                            claims: claims,
                            expires: DateTime.Now.AddMinutes(30),
                            signingCredentials: creds);

                        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                        //set the JWT token in a cookie
                        HttpContext.Response.Cookies.Append("JwtToken",tokenString,
                            new CookieOptions
                            {
                                HttpOnly = true,
                                Secure = true,
                                SameSite = SameSiteMode.Strict
                            });

                        // Optionally, you can store the token in a cookie or return it in the response
                        //HttpContext.Response.Cookies.Append("JwtToken", tokenString);
                        //return RedirectToAction("SecurePage");

                        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
                        return RedirectToAction("SecurePage");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Email or Password is not Correct");
                    }
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
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                ViewBag.Name = HttpContext.User.Identity.Name;
                Console.WriteLine("User is authenticated");
                return View();
            }
            else
            {
                Console.WriteLine("User is not authenticated");
                return RedirectToAction("Login", "Account");
            }
        }
        [HttpPost]
        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Response.Cookies.Delete("JwtToken");
            return RedirectToAction("Index","Home");
        }
     
    }
}
