using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace Authentication_Playground_.Controllers
{
    public class AccountController : Controller
    {
        AppDbContext _dbContext;

        public AccountController(AppDbContext dbContext) 
        { 
            _dbContext = dbContext;
        }

        public IActionResult Register()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LoginUser(string username, string password)
        {
            Users? user = await _dbContext.Users.Where(s => s.Username == username).FirstOrDefaultAsync();

            if (user == null) 
            {
                ViewBag.CredentialError = "NotExist";
                return View("Login");
            }

            //WARNING! NEVER DEPLOY THIS INTO PRODUCTION, THIS IS FOR A QUICK SHOWCASE,
            //YOU SHOULD ALWAYS KEEP PASSWORDS HASHED AND COMPARE THE HASHED VALUES
            if(string.Equals(password, user.Password))
            {
                return Redirect("~/Home/Index");
            }
            else
            {
                ViewBag.CredentialError = "Password";
                return View("Login");
            }
            
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser(string username, string password)
        {
            //WARNING! NEVER DEPLOY THIS INTO PRODUCTION, THIS IS FOR A QUICK SHOWCASE,
            //YOU SHOULD ALWAYS HASH PASSWORDS, THEN SAVE INTO DB
            Users newUser = new Users()
            {
                Username = username,
                Password = password
            };

            await _dbContext.Users.AddAsync(newUser);
            await _dbContext.SaveChangesAsync();
            return Redirect("~/Home/Index");
        }
    }
}
