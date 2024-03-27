using Authentication_Playground_.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Authentication_Playground_.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Register()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }
    }
}
