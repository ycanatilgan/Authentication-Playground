using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using System.Security.Cryptography;
using System.Text;

namespace Authentication_Playground_.Controllers
{
    public class AccountController : Controller
    {
        //For the tutorial, refer to http://ycanindev.com 
        AppDbContext _dbContext;

        private readonly byte[] key;

        public AccountController(AppDbContext dbContext) 
        { 
            _dbContext = dbContext;

            //REPLACE THIS KEY WITH YOUR OWN KEY DO NOT USE THE SAME!!!!!!!!!!!!!
            //This will be used to encrypt the mfa secret in the database
            //YOU CAN CREATE A RANDOM 32 byte key here: https://www.avast.com/random-password-generator
            key = Encoding.UTF8.GetBytes("pKjvjST5-oC+nDrz?sghX5GHo-cl4Obn");
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
            if (HttpContext.Session.GetString("UserId") != null)
            {
                //If user has MFA secret in the DB, do not create a secret and do not send to the view
                //Thus the view will show users already have MFA enabled
                if (_dbContext.Users
                    .Where(s => s.Id == HttpContext.Session.GetInt32("UserId") && s.MFASecret == null)
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
        public IActionResult LoginUser(string username, string password)
        {
            Users? user = _dbContext.Users.Where(s => s.Username == username).FirstOrDefault();

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
                    HttpContext.Session.SetInt32("OTPUserId", user.Id);
                    HttpContext.Session.SetInt32("OTPCounter", 3);
                    return View("MFAVerification");
                }

                HttpContext.Session.SetString("Username", user.Username);
                HttpContext.Session.SetInt32("UserId", user.Id);
                return Redirect("~/Home/Index");
            }
            else
            {
                ViewBag.CredentialError = "Password";
                return View("Login");
            }           
        }

        [HttpPost]
        public IActionResult RegisterUser(string username, string password)
        {
            //WARNING! NEVER DEPLOY THIS INTO PRODUCTION, THIS IS FOR A QUICK SHOWCASE,
            //YOU SHOULD ALWAYS HASH PASSWORDS, THEN SAVE INTO DB
            Users newUser = new Users()
            {
                Username = username,
                Password = password
            };

            _dbContext.Users.Add(newUser);
            _dbContext.SaveChanges();

            HttpContext.Session.SetString("Username", username);
            HttpContext.Session.SetInt32("UserId", newUser.Id);

            return Redirect("~/Home/Index");
        }

        [HttpPost]
        public IActionResult RegisterMFASecret(string AuthCode)
        {
            //Get the MFA secret you created on the User Management Page
            var secret = TempData["MFASecret"];

            if (secret == null)
            {
                Response.StatusCode = 400;
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
                Users user = _dbContext.Users.Where(s => s.Id == HttpContext.Session.GetInt32("UserId")).FirstOrDefault();

                //If user has MFA secret in the database, this request is going to override it.
                //We do not want this, MFA secrets cannot be simply overriden. This request is either malicious-
                //or buggy(For instance, if user has two active sessions, and try to set the secret-
                //at the same time.
                //MFA reset process should be complex and cannot be done easily.
                if (user.MFASecret != null)
                {
                    Response.StatusCode = 400;
                    return Redirect("~/Account/Management");
                }

                //Store the MFA Secret encrypted, I prefer to use AES
                //You can store in various ways, detail in the tutorial: http://ycanindev.com
                user.MFASecret = Encrypt(secret.ToString());
                _dbContext.SaveChanges();

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
        public IActionResult VerifyMFA(string AuthCode)
        {
            //Check the special session value to understand if user is entered their password correctly-
            //and redirected to the MFA page.
            //Also check the counter to limit the attempts, if more than 3, user will need to login back again
            var UserId = HttpContext.Session.GetInt32("OTPUserId");
            var Counter = HttpContext.Session.GetInt32("OTPCounter");
            if (UserId != null && Counter.HasValue && Counter > 0)
            {
                //Get the secret from database, and compute the correct otp code to see if it matches
                var user = _dbContext.Users.Where(s => s.Id == UserId).FirstOrDefault();

                if(user == null || user.MFASecret == null)
                {
                    Response.StatusCode = 400;
                    return Redirect("Login");
                }

                //Decrypt to get the true secret
                string secret = Decrypt(user.MFASecret);

                var totp = new Totp(Base32Encoding.ToBytes(secret.ToString()));
                var totpCode = totp.ComputeTotp(DateTime.UtcNow.AddSeconds(-1));

                if (AuthCode == totpCode)
                {
                    HttpContext.Session.Remove("OTPUserId");
                    HttpContext.Session.Remove("OTPCounter");

                    HttpContext.Session.SetString("Username", user.Username);
                    HttpContext.Session.SetInt32("UserId", user.Id);
                    return Redirect("~/Home/Index");
                }
                else
                {
                    int remainingCounter = Counter.Value - 1;

                    //If user has tried 3 times and none of them was successful, direct them to the login page again, or even ban the ip
                    if(remainingCounter <= 0)
                    {
                        HttpContext.Session.Remove("OTPUserId");
                        HttpContext.Session.Remove("OTPCounter");

                        ViewBag.CredentialError = "You need to login again!";
                        Response.StatusCode = 401;
                        return Redirect("Login");
                    }

                    ViewBag.MFAError = "WrongCode";
                    HttpContext.Session.SetInt32("OTPCounter", remainingCounter);
                    return View("MFAVerification");
                }
            }
            else
            {
                Response.StatusCode = 401;
                return Redirect("Login");
            }
        }

        private string Encrypt(string input)
        {
            using (Aes aes = Aes.Create())
            {
                //Create IV to give uniquness to each entity
                //More detail in the tutorial http://ycanindev.com

                byte[] randomBytes = new byte[16];
                new Random().NextBytes(randomBytes);
                byte[] iv = randomBytes;

                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(input);
                        }
                    }

                    //I prefer to add a prefix ("enc:" here)  to understand if data is encrypted or not in a simple way.
                    //Add iv in plain text and split it by encrypted data, the decrypt method will further understand-
                    //this structure and proccesses accordingly.
                    return "enc:" + Convert.ToBase64String(iv) + ":::" + Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private string Decrypt(string input)
        {
            //Check if data is encrypted
            //You can handle this error in your own way, I'll just throw an exception to stop the process.
            if (string.IsNullOrEmpty(input) || !input.StartsWith("enc:"))
                throw new Exception("The input isn't encrypted");

            using (Aes aes = Aes.Create())
            {
                //Strip off the "enc:" prefix
                input = input.Substring(4);
                var parts = input.Split(":::");

                //Split the IV and the encrypted value
                aes.Key = key;
                aes.IV = Convert.FromBase64String(parts[0]);

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(parts[1])))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
