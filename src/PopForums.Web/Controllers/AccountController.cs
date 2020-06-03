using IdentityModel;
using IdentityModel.Client;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using PopForums.Configuration;
using PopForums.ExternalLogin;
using PopForums.Models;
using PopForums.Mvc.Areas.Forums.Authorization;
using PopForums.Mvc.Areas.Forums.Services;
using PopForums.Services;
using PopForums.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace PopForums.Mvc.Controllers
{
	public class AccountController : Controller
	{
		private const string LoginProviderName = "IdentityServer4";

		private readonly IExternalUserAssociationManager _externalUserAssociationManager;
		private readonly IUserService _userService;
		private readonly IConfig _config;
		private readonly IAutoProvisionAccountService _autoProvisionAccountService;

		private static HttpClient _client = new HttpClient();

		public AccountController(IExternalUserAssociationManager externalUserAssociationManager, IUserService userService, IConfig config, IAutoProvisionAccountService autoProvisionAccountService)
		{
			_externalUserAssociationManager = externalUserAssociationManager;
			_userService = userService;
			_config = config;
			_autoProvisionAccountService = autoProvisionAccountService;
		}

		public IActionResult Login(string returnUrl = null)
		{
			if (string.IsNullOrEmpty(returnUrl))
				returnUrl = "/Forums";

			var callbackUrl = Url.Action("LoginCallback", new { returnUrl = returnUrl });

			return Challenge(new AuthenticationProperties { RedirectUri = callbackUrl }, OpenIdConnectDefaults.AuthenticationScheme);
		}

		public async Task<IActionResult> LoginCallbackAsync(string returnUrl = null)
		{
			if (string.IsNullOrEmpty(returnUrl))
				returnUrl = "/Forums";

			var externalAuthentication = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

			var accessToken = externalAuthentication.Properties.GetTokenValue("access_token");
			var idToken = externalAuthentication.Properties.GetTokenValue("id_token");


			var disco = await _client.GetDiscoveryDocumentAsync(Startup.AuthorityAddress);

			if (disco.IsError)
				throw new Exception(disco.Error);


			var userInfoResponse = await _client.GetUserInfoAsync(new UserInfoRequest
			{
				Address = disco.UserInfoEndpoint,
				Token = accessToken
			});

			if (userInfoResponse.IsError)
				throw new Exception(userInfoResponse.Error);


			bool isEmailVerified;
			if (!bool.TryParse(userInfoResponse.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.EmailVerified)?.Value, out isEmailVerified))
				isEmailVerified = false;

			if (!isEmailVerified)
				throw new Exception("External account must be verified.");

			var userIdClaim = userInfoResponse.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Subject) ??
							  userInfoResponse.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier) ??
							  throw new Exception("Unable to get user ID.");

			var emailClaim = userInfoResponse.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email) ??
							 userInfoResponse.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email) ??
							 throw new Exception("Unable to get user email.");

			var usernameClaim = userInfoResponse.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name) ??
								userInfoResponse.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.PreferredUserName) ??
								userInfoResponse.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name) ??
								throw new Exception("Unable to get user username.");

			var userId = userIdClaim.Value;
			var email = emailClaim.Value;
			var username = usernameClaim.Value;

			var ip = HttpContext.Connection.RemoteIpAddress.ToString();

			var externalLoginInfo = new ExternalLoginInfo(LoginProviderName, userId, username);
			var matchResult = await _externalUserAssociationManager.ExternalUserAssociationCheck(externalLoginInfo, ip);
			if (matchResult.Successful)
			{
				await _userService.Login(matchResult.User, ip);
				await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
				await PerformSignInAsync(matchResult.User, idToken);
				return Redirect(returnUrl);
			}

			if (_config.ExternalLoginOnly)
			{
				var user = await _autoProvisionAccountService.AutoProvisionAccountAsync(username, email, ip);

				await _userService.Login(user, ip);
				externalLoginInfo = new ExternalLoginInfo(LoginProviderName, userId, user.Name);
				await _externalUserAssociationManager.Associate(user, externalLoginInfo, ip);
				await PerformSignInAsync(user, idToken);
				return Redirect(returnUrl);
			}

			return Redirect("/");
		}

		private async Task PerformSignInAsync(User user, string idToken)
		{
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.Name, user.Name)
			};

			var props = new AuthenticationProperties()
			{
				IsPersistent = true,
				ExpiresUtc = DateTime.UtcNow.AddYears(1),
			};

			props.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });

			var id = new ClaimsIdentity(claims, PopForumsAuthorizationDefaults.AuthenticationScheme);
			await HttpContext.SignInAsync(PopForumsAuthorizationDefaults.AuthenticationScheme, new ClaimsPrincipal(id), props);
		}

		public async Task<IActionResult> Logout(string returnUrl = null)
		{
			if (string.IsNullOrEmpty(returnUrl))
				returnUrl = "/Forums";

			var callbackUrl = Url.Action("LogoutCallback", new { returnUrl = returnUrl });

			var result = await HttpContext.AuthenticateAsync(PopForumsAuthorizationDefaults.AuthenticationScheme);
			var idToken = result.Properties?.GetTokenValue("id_token");

			var props = new AuthenticationProperties { RedirectUri = callbackUrl };

			props.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });

			return SignOut(props, PopForumsAuthorizationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
		}

		public async Task<IActionResult> LogoutCallback(string returnUrl = null)
		{
			if (string.IsNullOrEmpty(returnUrl))
				returnUrl = "/Forums";

			return Redirect(returnUrl);
		}
	}
}
