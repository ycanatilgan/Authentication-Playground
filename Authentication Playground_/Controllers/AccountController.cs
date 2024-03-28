using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using System.Diagnostics;
using static System.Net.WebRequestMethods;

namespace Authentication_Playground_.Controllers
{
    public class AccountController : Controller
    {
        //For the tutorial, refer to http://ycanindev.com 
        AppDbContext _dbContext;

        public AccountController(AppDbContext dbContext) 
        { 
            _dbContext = dbContext;
        }

        //Register page
        public IActionResult Register()
        {
            return View();
        }

        //Login page
        public IActionResult Login()
        {
            return View();
        }

        //MFA Verification page after succesful login
        public IActionResult MFAVerification()
        {
            return View();
        }

        //User Management page, where they can set MFA Secret
        public IActionResult Management()
        {
            //If no username exists in the session, then it is unauthorized attempt, redirect to login page
            if (HttpContext.Session.GetString("Username") != null)
            {
                //If user has MFA secret in the DB, do not create a secret and do not send to the view
                //Thus the view will show users already have MFA enabled
                if (_dbContext.Users
                    .Where(s => s.Username == HttpContext.Session.GetString("Username") && s.MFASecret == null)
                    .Any())
                {
                    //Remove older created MFA secrets in any case
                    TempData.Remove("MFASecret");

                    //CREATE a random key with OTP.NET package, convert it into base 64 and-
                    //send it to view to allow users to scan the code and create their OTP codes.
                    //Save it into TempData, so that you can later get it and compute the code-
                    //to check if user is able to setup it correctly
                    var key = KeyGeneration.GenerateRandomKey(20);
                    string base64Key = Base32Encoding.ToString(key);
                    TempData["MFASecret"] = base64Key;

                    return View("Management", base64Key);
                }
                else
                {
                    return View("Management", string.Empty);
                }
            }
            else
            {
                Response.StatusCode = 401;
                return Redirect("Login");
            }
        }

        //Clear session, redirect to home after logout request
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return Redirect("~/Home/Index");
        }

        [HttpPost]
        public async Task<IActionResult> LoginUser(string username, string password)
        {
            Users? user = await _dbContext.Users.Where(s => s.Username == username).FirstOrDefaultAsync();

            //Check if username exists in db
            if (user == null) 
            {
                ViewBag.CredentialError = "NotExist";
                return View("Login");
            }

            //WARNING! NEVER DEPLOY THIS INTO PRODUCTION, THIS IS FOR A QUICK SHOWCASE,
            //YOU SHOULD ALWAYS KEEP PASSWORDS HASHED AND COMPARE THE HASHED VALUES
            if(string.Equals(password, user.Password))
            {
                //If user has MFA secret in the DB, then user has to enter their OTP code to login
                //If no MFA secret is available, you can authenticate the user, since they did not-
                //have MFA configured.
                if(user.MFASecret != null)
                {
                    //Careful here. You have to give user a some kind of server side verification-
                    //to allow them enter their 2-step code and login. You cannot only trust client-
                    //side. You can give them a special session value that confirms they have entered-
                    //their password correctly and can login only by entering their 2-step code
                    //You can find more info in: http://ycanindev.com
                    HttpContext.Session.SetString("OTPUsername", user.Username);
                    return View("MFAVerification");
                }

                HttpContext.Session.SetString("Username", user.Username);
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

            HttpContext.Session.SetString("Username", username);
            await _dbContext.Users.AddAsync(newUser);
            await _dbContext.SaveChangesAsync();
            return Redirect("~/Home/Index");
        }

        [HttpPost]
        public async Task<IActionResult> RegisterMFASecret(string AuthCode)
        {
            //Get the MFA secret you created on the User Management Page
            var secret = TempData["MFASecret"];

            if (secret == null)
            {
                Response.StatusCode = 500;
                return Redirect("~/Account/Management");
            }

            //Compute the correct OTP code with the secret you created before
            //I prefer to set -1 second bias to eliminate human delays and network delays
            var totp = new Totp(Base32Encoding.ToBytes(secret.ToString()));
            var totpCode = totp.ComputeTotp(DateTime.UtcNow.AddSeconds(-1));

            //If computed key and the user entered key matches, it means setup is succesful and you-
            //can update the user with the secret
            if (AuthCode == totpCode)
            {
                Users user = await _dbContext.Users.Where(s => s.Username == HttpContext.Session.GetString("Username")).FirstOrDefaultAsync();
                user.MFASecret = secret.ToString();
                await _dbContext.SaveChangesAsync();

                TempData.Remove("MFASecret");
                return View("Management", null);
            }
            else
            {
                ViewBag.MFAError = "WrongCode";
                return View("Management", TempData["MFASecret"]);
            }           
        }

        [HttpPost]
        public async Task<IActionResult> VerifyMFA(string AuthCode)
        {
            //Check the special session value to understand if user is entered their password correctly-
            //and redirected to the MFA page.
            var username = HttpContext.Session.GetString("OTPUsername");
            if (username != null)
            {
                //Get the secret from database, and compute the correct otp code to see if it matches
                string secret = await _dbContext.Users.Where(s => s.Username == username).Select(s => s.MFASecret).FirstOrDefaultAsync();
                var totp = new Totp(Base32Encoding.ToBytes(secret.ToString()));
                var totpCode = totp.ComputeTotp(DateTime.UtcNow.AddSeconds(-1));

                if (AuthCode == totpCode)
                {
                    HttpContext.Session.Remove("OTPUsername");
                    HttpContext.Session.SetString("Username", username);
                    return Redirect("~/Home/Index");
                }
                else
                {
                    ViewBag.MFAError = "WrongCode";
                    return View("MFAVerification");
                }
            }
            else
            {
                Response.StatusCode = 401;
                return Redirect("Login");
            }
        }
    }
}
