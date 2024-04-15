using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Fido2Identity;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System.Text;
using System.Threading;
using UAParser;

namespace Authentication_Playground_.Controllers
{
    public class Fido2Controller : Controller
    {
        //For the tutorial, refer to https://ycanindev.com 
        #region Initializers and  variables
        private readonly AppDbContext _dbContext;

        private readonly Fido2 _lib;
        private readonly IOptions<Fido2Configuration> _optionsFido2Configuration;

        private readonly Fido2Storage fido2Storage;

        public Fido2Controller(AppDbContext dbContext, IOptions<Fido2Configuration> optionsFido2Configuration) 
        { 
            _dbContext = dbContext;

            _optionsFido2Configuration = optionsFido2Configuration;
            _lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = _optionsFido2Configuration.Value.ServerDomain,
                ServerName = _optionsFido2Configuration.Value.ServerName,
                Origin = _optionsFido2Configuration.Value.Origin,
                TimestampDriftTolerance = _optionsFido2Configuration.Value.TimestampDriftTolerance
            });

            fido2Storage = new Fido2Storage(dbContext);
        }
        #endregion

        #region Forms & Requests
        #region REGISTER PASSKEY
        [HttpPost]
        public IActionResult RegisterRequest()
        {
            if (HttpContext.Session.GetInt32("UserId").HasValue)
            {
                Users? user = _dbContext.Users.Where(s => s.Id == HttpContext.Session.GetInt32("UserId").Value).FirstOrDefault();

                if (user == null)
                    return BadRequest();

                if(user.UserHandle == null)
                {
                    byte[] userIdBytes = new byte[32];
                    new Random().NextBytes(userIdBytes);
                    string userIdStr = Convert.ToBase64String(userIdBytes);

                    user.UserHandle = userIdStr;
                    _dbContext.SaveChanges();
                }

                var userHandle = Convert.FromBase64String(user.UserHandle);

                var fidoUser = new Fido2User
                {
                    DisplayName = user.Username,
                    Name = user.Username,
                    Id = userHandle
                };

                // 2. Get user existing keys by user
                var items = fido2Storage.GetCredentialsByUsername(user.Username);
                var existingKeys = new List<PublicKeyCredentialDescriptor>();
                foreach (var publicKeyCredentialDescriptor in items)
                {
                    existingKeys.Add(publicKeyCredentialDescriptor.Descriptor);
                }

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    RequireResidentKey = false,
                    UserVerification = UserVerificationRequirement.Required
                };

                authenticatorSelection.AuthenticatorAttachment = AuthenticatorAttachment.Platform;

                var exts = new AuthenticationExtensionsClientInputs() { Extensions = true };

                var options = _lib.RequestNewCredential(fidoUser, existingKeys, authenticatorSelection, AttestationConveyancePreference.Direct, exts);
                options.Rp = new PublicKeyCredentialRpEntity("localhost", "YcanInDev", null);

                List<PubKeyCredParam> pubKeyCredParams = new List<PubKeyCredParam>
                {
                    new PubKeyCredParam(COSE.Algorithm.ES256, PublicKeyCredentialType.PublicKey),
                    new PubKeyCredParam(COSE.Algorithm.RS256, PublicKeyCredentialType.PublicKey)
                };
                options.PubKeyCredParams = pubKeyCredParams;
                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

                // 5. return options to client
                return Json(options);
            }
            else
            {
                Response.StatusCode = 401;
                return Json("Unauthorized");
            }
        }

        [HttpPost]
        public async Task<IActionResult> RegisterResponse([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            try
            {
                if (HttpContext.Session.GetInt32("UserId").HasValue != false)
                {
                    var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                    var options = CredentialCreateOptions.FromJson(jsonOptions);

                    // 2. Create callback so that lib can verify credential id is unique to this user
                    async Task<bool> callback(IsCredentialIdUniqueToUserParams args, CancellationToken token)
                    {
                        var users = await fido2Storage.GetUsersByCredentialIdAsync(args.CredentialId);
                        if (users.Count > 0) 
                            return false;

                        return true;
                    };

                    // 2. Verify and make the credentials
                    var success = await _lib.MakeNewCredentialAsync(attestationResponse, options, callback);

                    string deviceInfo = "";
                    try
                    {
                        var userAgent = HttpContext.Request.Headers["User-Agent"];
                        var uaParser = Parser.GetDefault();
                        ClientInfo c = uaParser.Parse(userAgent);

                        deviceInfo = c.OS.Family.ToString();
                    }
                    catch { }

                    // 3. Store the credentials in db
                    await fido2Storage.AddCredentialToUser(options.User, new FidoStoredCredential
                    {
                        Username = options.User.Name,
                        Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                        PublicKey = success.Result.PublicKey,
                        UserHandle = success.Result.User.Id,
                        SignatureCounter = success.Result.Counter,
                        CredType = success.Result.CredType,
                        RegDate = DateTime.Now,
                        LastLogin = DateTime.Now,
                        AaGuid = success.Result.Aaguid,
                        DeviceInfo = deviceInfo
                    });

                    // 4. return "ok" to the client
                    return Ok();
                }
                else
                {
                    Response.StatusCode = 401;
                    return Json("Unauthorized");
                }
            }
            catch (Exception ex)
            {
                Response.StatusCode = 500;
                return Json("Unexpected error");
            }

        }
        #endregion

        #region SIGN IN WITH PASS KEY
        [HttpPost]
        public async Task<JsonResult> SignInRequest()
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            var exts = new AuthenticationExtensionsClientInputs() { Extensions = true };
            
            // 3. Create options
            var uv = UserVerificationRequirement.Required;
            var options = _lib.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            options.RpId = "localhost";

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        [HttpPost]
        public async Task<IActionResult> VerifyWebAuthn([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
        {

            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                // 2. Get registered credential from database
                var creds = await fido2Storage.GetCredentialById(clientResponse.Id);

                if (creds == null)
                {
                    TempData["Unsuccessful"] = "Bilinmeyen kimlik bilgileri";
                    return Unauthorized();
                }

                // 3. Get credential counter from database
                var storedCounter = creds.SignatureCounter;

                // 4. Create callback to check if userhandle owns the credentialId
                async Task<bool> callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken token)
                {
                    var storedCreds = await fido2Storage.GetCredentialsByUserHandleAsync(args.UserHandle);
                    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
                }

                // 5. Make the assertion
                var res = await _lib.MakeAssertionAsync(clientResponse, options, creds.PublicKey, storedCounter, callback);

                var userHandleFromRequest = Convert.ToBase64String(creds.UserHandle);

                var user = _dbContext.Users.Where(s => s.UserHandle == userHandleFromRequest).Select(s => new Users
                {
                    Id = s.Id,
                    UserHandle = s.UserHandle,
                    Username = s.Username
                }).FirstOrDefault();

                if (user == null || string.IsNullOrEmpty(user.UserHandle))
                {
                    ViewBag.SigninMessage = "User not found";
                    return View("Login");
                }

                // 6. Store the updated counter
                await fido2Storage.UpdateCounter(res.CredentialId, res.Counter);

                HttpContext.Session.SetString("Username", user.Username);
                HttpContext.Session.SetInt32("UserId", user.Id);

                return Redirect("~/Home/Index");
            }
            catch (Exception ex)
            {
                ViewBag.SigninMessage = "Your passkey could not be verified";
                return View("Login");
            }
        }
        #endregion
        #endregion

        #region Private Functions

        #endregion
    }
}
