using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Fido2Identity;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text;
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
        [HttpPost]
        public IActionResult RegisterRequest()
        {
            if (HttpContext.Session.GetInt32("UserId").HasValue)
            {
                Users? user = _dbContext.Users.Where(s => s.Id == HttpContext.Session.GetInt32("UserId").Value).Select(s => new Users
                {
                    UserHandle = s.UserHandle,
                    Username = s.Username
                }).FirstOrDefault();

                var userHandle = Convert.FromBase64String(user.UserHandle);

                var fidoUser = new Fido2User
                {
                    DisplayName = user.Username,
                    Name = user.Username,
                    Id = userHandle
                };

                // 2. Get user existing keys by user
                var items = fido2Storage.GetCredentialsByUserHandle(userHandle);
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
                options.Rp = new PublicKeyCredentialRpEntity("localhost:44373", "YcanInDev", null);

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
                return Redirect("Login");
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
                    IsCredentialIdUniqueToUserAsyncDelegate callback = IsCredentialIdUniqueToUserAsyncDelegate;

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

                    //var user = await accountManager.(options.User.Name);
                    // await _userManager.GetUserAsync(User);

                    /*if (user == null)
                    {
                        Response.StatusCode = 500;
                        return Json(new CredentialMakeResult { Status = "error", ErrorMessage = $"Unable to load user with ID '{_userManager.GetUserId(User)}'." });
                    }*/

                    //await _userManager.SetTwoFactorEnabledAsync(user, true);
                    //var userId = await _userManager.FindByNameAsync(user);

                    return Ok();
                }
                else
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }

        public async Task<bool> IsCredentialIdUniqueToUserAsyncDelegate(IsCredentialIdUniqueToUserParams credentialIdUserHandleParams, CancellationToken cancellationToken)
        {
            // Implement your logic here
            // This method should return a Task<bool>
            var userList = await fido2Storage.GetUsersByCredentialIdAsync(credentialIdUserHandleParams.CredentialId);

            foreach (var user in userList)
            {
                if (user.Id != credentialIdUserHandleParams.User.Id)
                    return false;
            }

            return true;
        }
        #endregion

        #region Private Functions

        #endregion
    }
}
