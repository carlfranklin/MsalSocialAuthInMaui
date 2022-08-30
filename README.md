# Table of Contents

- [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Prerequisites](#prerequisites)
    - [.NET 6.0](#net-60)
    - [Visual Studio 2022](#visual-studio-2022)
    - [Required Workloads](#required-workloads)
  - [Demo](#demo)
    - [Clone the MsalAuthInMaui Repo](#clone-the-msalauthinmaui-repo)
    - [Add appsettings.json Support](#add-appsettingsjson-support)
      - [*NestedSettings.cs*](#nestedsettingscs)
      - [*Settings.cs*](#settingscs)
    - [Refactor the PCAWrapper Class](#refactor-the-pcawrapper-class)
    - [Add Twitter Authentication Support](#add-twitter-authentication-support)
      - [Create an Azure Active Directory B2C tenant](#create-an-azure-active-directory-b2c-tenant)
      - [Configure your Azure Active Directory B2C tenant](#configure-your-azure-active-directory-b2c-tenant)
      - [Setup Twitter Identity Provider](#setup-twitter-identity-provider)
      - [Create a User Flow](#create-a-user-flow)
      - [Test User Flow](#test-user-flow)
    - [Add Twitter Authentication Support in MAUI](#add-twitter-authentication-support-in-maui)
      - [*IPCAWrapper.cs*](#ipcawrappercs)
      - [*PCAWrapper.cs*](#pcawrappercs)
      - [*PCASocialWrapper.cs*](#pcasocialwrappercs)
      - [Sign in with Twitter](#sign-in-with-twitter)
      - [Create an Account with Email](#create-an-account-with-email)
    - [Verify Accounts](#verify-accounts)
  - [Summary](#summary)
  - [Complete Code](#complete-code)
  - [Resources](#resources)

## Introduction

In this episode, we are going to add social authorization support to the [MsalAuthInMaui](https://github.com/carlfranklin/MsalAuthInMaui) repo we built in the last episode.

> Note: Some of the images will not have correct resource names. The most important thing is that the configuration settings are correct.

We are going to start by enhancing the repo by writing some code to move out hard-coded settings, to an *appsettings.json* file. MAUI does not come with an *appsettings.json* file, but we are going to make that happen. We are going to follow James Montemagno's post [App Configuration Settings in .NET MAUI (appsettings.json)](https://montemagno.com/dotnet-maui-appsettings-json-configuration/) with some minor changes to meet our needs.

End results will look like this:.

<img src="md-images/image-20220830134051446.png" alt="image-20220830134051446" style="zoom: 67%;" />

Let's get to it.

## Prerequisites

The following prerequisites are needed for this demo.

### .NET 6.0

Download the latest version of the .NET 6.0 SDK [here](https://dotnet.microsoft.com/en-us/download).

### Visual Studio 2022

For this demo, we are going to use the latest version of [Visual Studio 2022](https://visualstudio.microsoft.com/vs/community/).

### Required Workloads

In order to build ASP.NET Core Web API applications, the `ASP.NET and web development` workload needs to be installed. In order to build `.NET MAUI` applications, you also need the `.NET Multi-platform App UI development` workload, so if you do not have them installed let's do that now.

![.NET Multi-platform App UI development](md-images/34640f10f2d813f245973ddb81ffa401c7366e96e625b3e59c7c51a78bbb2056.png)  

## Demo

In the following demo let's start by cloning the `MsalAuthInMaui` repo, and then move out the hard-coded settings to an *appsettings.json* file.

### Clone the MsalAuthInMaui Repo

Clone the [MsalAuthInMaui](https://github.com/carlfranklikn/MsalAuthInMaui) repo and rename the folder MsalSocialAuthInMaui

```powershell
git clone https://github.com/carlfranklin/MsalAuthInMaui
```

### Add appsettings.json Support

Open the *MsalAuthInMaui.sln* solution, and add the following NuGet packages to the *MsalAuthInMaui.csproj* project, by following the following commands in the `Package Manager Console`.

![Package Manager Console](md-images/ca1bae664dc62f24fbf96756018ab784445cc17c9e22de687cd0d3bde7d30411.png)  

```powershell
install-package Microsoft.Extensions.Configuration.Binder
install-package Microsoft.Extensions.Configuration.Json
install-package Newtonsoft.Json
```

>:blue_book: Make sure you select the MsalAuthInMaui project.

![Install Packages](md-images/269c3663dc92156fdb411b14fbd976ee993f39c4f93cc6aa9e3fbeee1d8ea231.png)

Add a new *appsettings.json* file to the *MsalAuthInMaui.csproj* project.

![Add a appsettings.json File](md-images/b746252dace39467cf28cce11251e5f356bd795556f3aec971344fa7d9a5aa29.png)  

![appsettings.json File](md-images/1ffa11d7fb03649d26597274ac047bb8ad30575145280402095cfec19a353176.png)  

Change the Build Action to Embedded resource.

![Add a appsettings.json File](md-images/2848c1ab2f92466b1997aa0639be7e5708e9d839709a82fedcdd0e7f35ed5592.png)  

Add the following code to the *appsettings.json* file:

```json
{
  "Settings": {
    "ClientId": "REPLACE-WITH-YOUR-CLIENT-ID",
    "TenantId": "REPLACE-WITH-YOUR-TENANT-ID",
    "Authority": "https://login.microsoftonline.com/REPLACE-WITH-YOUR-TENANT-ID",
    "Scopes": [
        { "Value": "api://REPLACE-WITH-YOUR-CLIENT-ID/access_as_user" }
      ]
    }
}
```

>:point_up: Replace your ClientId, and TenantId with your own values from Azure B2C settings. See episode 24 for details.

Add two new classes *NestedSettings.cs*, and *Settings.cs*, and add the following code:

#### *NestedSettings.cs*

```csharp
namespace MsalAuthInMaui
{
    public class NestedSettings
    {
        public string Value { get; set; } = null;
    }
}
```

#### *Settings.cs*

```csharp
namespace MsalAuthInMaui
{
    public class Settings
    {
        public string ClientId { get; set; } = null;
        public string TenantId { get; set; } = null;
        public string Authority { get; set; } = null;
        public NestedSettings[] Scopes { get; set; } = null;
    }
}
```

At this point, we have everything ready to get the values from *appsettings.json*, and assign them to the Settings class. Let's open the *MauiProgram.cs* file, and add the following two using statements:

```csharp
global using Microsoft.Extensions.Configuration;
global using System.Reflection;
```

Now, we are going to use Reflection to get the values from the *appsettings.json* file, and a `ConfigurationBuilder` to the builder process. We are also going to add our `MainPage` as a transient service, and make a small change to it.

Add the following code below `ConfigureFonts` in the *MauiProgram.cs* file:

```csharp
var executingAssembly = Assembly.GetExecutingAssembly();

using var stream = executingAssembly.GetManifestResourceStream("MsalAuthInMaui.appsettings.json");

var configuration = new ConfigurationBuilder()
            .AddJsonStream(stream)
            .Build();

builder.Services.AddTransient<MainPage>();

builder.Configuration
    .AddConfiguration(configuration);
```

The complete code should look like this:

```csharp
using Microsoft.Extensions.Configuration;
using System.Reflection;

namespace MsalAuthInMaui
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
                });

            var executingAssembly = Assembly.GetExecutingAssembly();

            using var stream = executingAssembly.GetManifestResourceStream("MsalAuthInMaui.appsettings.json");

            var configuration = new ConfigurationBuilder()
                        .AddJsonStream(stream)
                        .Build();

            builder.Services.AddTransient<MainPage>();

            builder.Configuration
                .AddConfiguration(configuration);

            return builder.Build();
        }
    }
}
```

Then change the *App.xaml.cs* file to accept the `MainPage` we just defined as a transient service in the *MauiProgram.cs* file:

```csharp
namespace MsalAuthInMaui
{
    public partial class App : Application
    {
        public App(MainPage page)
        {
            InitializeComponent();

            MainPage = page;
        }
    }
}
```

Now we are all setup to read *appsettings.json* settings, and have them easily accesible in our `Settings` class.

#### Add an Extension Method

Add a new *Extensions.cs* class with the following code:

```csharp
using Newtonsoft.Json;
using System.Text;

namespace MsalAuthInMaui
{
    public static class Extensions
    {
        public static StringContent ToJsonStringContent(this object o) => new(JsonConvert.SerializeObject(o), Encoding.UTF8, "application/json");

        public static string[] ToStringArray(this NestedSettings[] nestedSettings)
        {
            string[] result = new string[nestedSettings.Length];

            for (int i = 0; i < nestedSettings.Length; i++)
            {
                result[i] = nestedSettings[i].Value;
            }

            return result;
        }
    }
}
```

### Refactor the PCAWrapper Class

We are going to refactor the PCAWrapper class provided by Microsoft in [Microsoft identity platform code samples](https://docs.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code), to accept an `IConfiguration` object, and set our new `Settings` property, to remove all hard-coded values.

Open the *PCAWrapper.cs* file, and replace the code with this:

```csharp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using static System.Formats.Asn1.AsnWriter;

namespace MsalAuthInMaui
{
    /// <summary>
    /// This is a wrapper for PCA. It is singleton and can be utilized by both application and the MAM callback
    /// </summary>
    public class PCAWrapper
    {
        private IConfiguration _configuration;
        private static Settings _settings { get; set; }

        internal IPublicClientApplication PCA { get; }

        internal bool UseEmbedded { get; set; } = false;
        public string[] Scopes { get; set; }

        // public constructor
        public PCAWrapper(IConfiguration configuration)
        {
            _configuration = configuration;
            _settings = _configuration.GetRequiredSection("Settings").Get<Settings>();
            Scopes = _settings.Scopes.ToStringArray();

            // Create PCA once. Make sure that all the config parameters below are passed
            PCA = PublicClientApplicationBuilder
                                        .Create(_settings.ClientId)
                                        .WithRedirectUri(PlatformConfig.Instance.RedirectUri)
                                        .WithIosKeychainSecurityGroup("com.microsoft.adalcache")
                                        .Build();
        }

        /// <summary>
        /// Acquire the token silently
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string[] scopes)
        {
            var accts = await PCA.GetAccountsAsync().ConfigureAwait(false);
            var acct = accts.FirstOrDefault();

            var authResult = await PCA.AcquireTokenSilent(scopes, acct)
                                        .ExecuteAsync().ConfigureAwait(false);
            return authResult;

        }

        /// <summary>
        /// Perform the interactive acquisition of the token for the given scope
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenInteractiveAsync(string[] scopes)
        {
            var systemWebViewOptions = new SystemWebViewOptions();
#if IOS
            // embedded view is not supported on Android
            if (UseEmbedded)
            {

                return await PCA.AcquireTokenInteractive(scopes)
                                        .WithUseEmbeddedWebView(true)
                                        .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                        .ExecuteAsync()
                                        .ConfigureAwait(false);
            }

            // Hide the privacy prompt in iOS
            systemWebViewOptions.iOSHidePrivacyPrompt = true;
#endif

            return await PCA.AcquireTokenInteractive(scopes)
                                    .WithAuthority(_settings.Authority)
                                    .WithTenantId(_settings.TenantId)
                                    .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                    .WithUseEmbeddedWebView(true)
                                    .ExecuteAsync()
                                    .ConfigureAwait(false);
        }

        /// <summary>
        /// Signout may not perform the complete signout as company portal may hold
        /// the token.
        /// </summary>
        /// <returns></returns>
        public async Task SignOutAsync()
        {
            var accounts = await PCA.GetAccountsAsync().ConfigureAwait(false);
            foreach (var acct in accounts)
            {
                await PCA.RemoveAsync(acct).ConfigureAwait(false);
            }
        }
    }
}
```

Finally, open up the *MainPage.xaml.cs* file, and replace the code with the following:

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

namespace MsalAuthInMaui
{
    public partial class MainPage : ContentPage
    {
        private string _accessToken = string.Empty;
        private PCAWrapper _pcaWrapper;
        private IConfiguration _configuration;

        bool _isLoggedIn = false;
        public bool IsLoggedIn
        {
            get => _isLoggedIn;
            set
            {
                if (value == _isLoggedIn) return;
                _isLoggedIn = value;
                OnPropertyChanged(nameof(IsLoggedIn));
            }
        }

        public MainPage(IConfiguration configuration)
        {
            _configuration = configuration;
            _pcaWrapper = new PCAWrapper(_configuration);
            BindingContext = this;
            InitializeComponent();
            _ = Login();
        }

        async private void OnLoginButtonClicked(object sender, EventArgs e)
        {
            await Login().ConfigureAwait(false);
        }

        private async Task Login()
        {
            try
            {
                // Attempt silent login, and obtain access token.
                var result = await _pcaWrapper.AcquireTokenSilentAsync(_pcaWrapper.Scopes).ConfigureAwait(false);
                IsLoggedIn = true;

                // Set access token.
                _accessToken = result.AccessToken;

                // Display Access Token from AcquireTokenSilentAsync call.
                await ShowOkMessage("Access Token from AcquireTokenSilentAsync call", _accessToken).ConfigureAwait(false);
            }
            // A MsalUiRequiredException will be thrown, if this is the first attempt to login, or after logging out.
            catch (MsalUiRequiredException)
            {
                // Perform interactive login, and obtain access token.
                var result = await _pcaWrapper.AcquireTokenInteractiveAsync(_pcaWrapper.Scopes).ConfigureAwait(false);
                IsLoggedIn = true;

                // Set access token.
                _accessToken = result.AccessToken;

                // Display Access Token from AcquireTokenInteractiveAsync call.
                await ShowOkMessage("Access Token from AcquireTokenInteractiveAsync call", _accessToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                IsLoggedIn = false;
                await ShowOkMessage("Exception in AcquireTokenSilentAsync", ex.Message).ConfigureAwait(false);
            }
        }

        async private void OnLogoutButtonClicked(object sender, EventArgs e)
        {
            // Log out.
            _ = await _pcaWrapper.SignOutAsync().ContinueWith(async (t) =>
            {
                await ShowOkMessage("Signed Out", "Sign out complete.").ConfigureAwait(false);
                IsLoggedIn = false;
                _accessToken = string.Empty;
            }).ConfigureAwait(false);
        }

        async private void OnGetWeatherForecastButtonClicked(object sender, EventArgs e)
        {
            // Call the Secure Web API to get the weatherforecast data.
            var weatherForecastData = await CallSecureWebApi(_accessToken).ConfigureAwait(false);

            // Show the data.
            if (weatherForecastData != string.Empty)
                await ShowOkMessage("WeatherForecast data", weatherForecastData).ConfigureAwait(false);
        }

        // Call the Secure Web API.
        private static async Task<string> CallSecureWebApi(string accessToken)
        {
            if (accessToken == string.Empty)
                return string.Empty;

            try
            {
                // Get the weather forecast data from the Secure Web API.
                var client = new HttpClient();

                // Create the request.
                var message = new HttpRequestMessage(HttpMethod.Get, "{REPLACE-WITH-YOUR-SECURE-WEB-API-URL}/weatherforecast");

                // Add the Authorization Bearer header.
                message.Headers.Add("Authorization", $"Bearer {accessToken}");

                // Send the request.
                var response = await client.SendAsync(message).ConfigureAwait(false);

                // Get the response.
                var responseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                // Return the response.
                return responseString;
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }

        private Task ShowOkMessage(string title, string message)
        {
            _ = Dispatcher.Dispatch(async () =>
            {
                await DisplayAlert(title, message, "OK").ConfigureAwait(false);
            });
            return Task.CompletedTask;
        }
    }
}
```

You must also replace `{REPLACE-WITH-YOUR-SECURE-WEB-API-URL}` with your secure web api url.

Now, you should be able to run the app, and everything should work as it did before.

### Add Twitter Authentication Support

We are going to add the ability to authenticate to our application with Twitter, and still be able to call our secure Web API.

Let's start by going to the Twitter's `Developer Platform` portal at (https://developer.twitter.com/). If you do not have an account, create an account at this time.

Click on `Developer Portal`:

![Developer Portal](md-images/215f9f304b7998203c0cebe326a920a4cd81bbf3944df0ed09b2b7902039b50b.png)  

Go to `Overview`.

![Overview](md-images/fa7f2707e9842d91901e2b57bb9bfac1d94633240e2893ae2eb62d30a6a53e76.png)  

Towards the bottom, click on `+ Create App`.

![Create App](md-images/a2cb5f042d6ee92fd01b4cdb0deff7691b81d3bb22d20758f316e4bad3141236.png)  

Give it a name, and click Next. I would encourage you to use `MsalAuthInMaui` with a unique suffix that identifies you, such your company or your name. In my case, my suffix is TDNS (The Dot Net Show), so I'm naming my app `MsalAuthInMauiTDNS`

<img src="md-images/image-20220830134759569.png" alt="image-20220830134759569" style="zoom:80%;" />



Copy your `API Key`, and `API Key Secret` in a safe place, as we are going to need them to set up our Twitter Identity Provider in Azure AD B2C, and we will not be able to retrieve those later. Then click on `App Settings`.

![Here are your keys & tokens](md-images/2ee1a277817897784ad143232bd030321ae04986ba3addf99cf9457a68ff66e9.png)  

In order to provide authentication support using Twitter, we need to setup `OAuth 2.0a Authentication`. Click on `Set up`.

![Set up](md-images/63dc5f6a60a533247f6b7a752bdfb62bc1b4968b1c8f8a1908c473fa5023a896.png)

Keep the defaults, and check `Native App`.

![Native App](md-images/fdd8f4cc3bf5827cf3878cc4175e70ada7ecb909410a7578d3a334f0ceeacc81.png)  

Enter the url to your up and coming b2c app registration which will be `https://msalauthinmaui{YOUR-SUFFIX-HERE}.b2clogin.com/msalauthinmaui{YOUR-SUFFIX-HERE}.onmicrosoft.com/b2c_1_twitter_susi/oauth1/authresp` for the `Callback URI / Redirect URL`, and give it a `Website URL`, and click `Save`. Make sure to replace {YOUR-SUFFIX-HERE} with your unique suffix.

![image-20220830135432255](md-images/image-20220830135432255.png)

You will be presented with your `OAuth 2.0 Client ID and Client Secret` screen. Store those values in a safe place. Click `Done`, and then `Yes, I saved it`.

![OAuth 2.0 Client ID and Client Secret](md-images/964534e10a607b0d6a55952d28b285664d7b06140a45b5a67f7711338843abcf.png)  

#### Create an Azure Active Directory B2C tenant

In the last episode, we went straight to `Azure B2C`, and created a new `App registration`. For social authentication, we will need to create a new tenant, so we can take advantage of the Azure's `Identity Providers` to allow social network authentication support, including Twitter, Google, Facebook, Apple, and others.

Go to [Azure](https://portal.azure.com/), and select your subscription.

Type `azure b2c` in the search box, and click on `Azure AD B2C`.

![Azure AD B2C](md-images/6de16366f91903a60682935857cb83247a76102ed48fe2dbbbf666c2208930cf.png)  

![Create an Azure AD B2C tenant Get started](md-images/ab8da0e12c5f7b00c0510d88fd3604097a83983188c18d0e0c355c8e6cf2eb39.png)  

>:point_up: In the last demo, we went to `Azure AD B2C`, and then straight to `App registrations` to setup our app. Notice that the left menu is missing things like `Identity Providers`, `API connectors`, `User Flows`, etc.

Click on `Get started`, under `Create an Azure AD B2C tenant`, to get the instructions on how to create a new Azure AD B2C tenant, which will include those missing items.

That should take you to [Tutorial: Create an Azure Active Directory B2C tenant](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-tenant?WT.mc_id=Portal-Microsoft_AAD_B2CAdmin) with instructions on to create an Azure AD B2C tenant. Follow the instructions, and make sure you set the `Initial domain name` to `MsalAuthInMaui{YOUR_SUFFIX}`. 

![Create an Azure AD B2C tenant Get started](md-images/bb8da0e12c5f7b00c0510d88fd3604097a83983188c18d0e0c355c8e6cf2eb39.png)  

#### Configure your Azure Active Directory B2C tenant

Once you create your new `MsalAuthInMaui` Azure B2C tenant, and switch to it, you should be able to see the following:

![Azure Active Directory B2C tenant](md-images/210c681399fad9fa12c717dc197f9ff56984f94f52c707e03a68089dc5ce1931.png) 

>:point_up: Notice that the left menu now has `Identity Providers`, `API connectors`, `User Flows`, etc.

As we did before, go to `App registrations`, add `New registration`, enter the following values, and click on `Register`.

![App registrations](md-images/28e46d3972e7139a595f1d24327fb1194be9f663c4be60e7b2445d4a014ac29c.png)  

| Setting                 | Value                                                        |
| ----------------------- | ------------------------------------------------------------ |
| Name                    | MsalAuthInMaui{YOUR-SUFFIX-HERE}                             |
| Supported account types | Accounts in any identity provider or organizational directory (for authenticating users with user flows) |
| Redirect URI            | Select Public client/native (mobile & desktop), and enter your redirect url from MainActivity.cs. Ex: msauth://com.companyname.msalauthinmaui/snaHlgr4autPsfVDSBVaLpQXnqU= |
| Permissions             | Check the Grant admin consent to openid and offline_access permissions box |

![Register App registration](md-images/105e014e1523a508971cbb3d32697f8a62a1ea8cbc8a90dcf62507a592743c79.png)  

Notice a new `Application (client) ID`, and `Directory (tenant) ID`, will be generated.

![Client and Tenant IDs](md-images/a1ae07eef467508dc4a3b9f94f3cd753cf33150032d83151a610c1652ff49b0d.png)  

Go ahead, and copy those new values, and replace the ones in the *appsettings.json* file of our `SecureWebApi` project.

Go to the new `App registration`.

![New App registration](md-images/733ee18a366562c91d32fdb615521f64dd704f316361694d55c5f4a0c09c5efe.png)  

Go to `Authentication`, click on `+ Add a platform`, then on Web.

![Add a platform](md-images/b3ec50c7f8a5f8dd55decf959222ead496bcde3d97ec8fb190de1afe20fff618.png)  

Enter your secure webapi url + "/signin-oidc". Ex: `https://as-securewebapi.azurewebsites.net/signin-oidc` as the Redirect URI, and check `Access tokens (used for implicit flows)`, and `ID tokens (used for implicit and hybrid flows`)

![Redirect URI](md-images/98e7e17b7f64695e670873d8929f8425ce343bcf7533188b93a6af6269b333ce.png)  

#### 

![](md-images/8e031f949927dca41c99aa063f6cf08d50aca2f866ba3cd957ea2891f7052a72.png)  

#### Add Twitter Callback URL

For the Web platform, click `Add URI` and copy the callback URL you set up in the Twitter account. This should be `https://msalauthinmaui{YOUR-SUFFIX}.b2clogin.com/msalauthinmaui{YOUR-SUFFIX}.onmicrosoft.com/b2c_1_twitter_susi/oauth1/authresp` with your suffix substituted

![image-20220830121556356](md-images/image-20220830121556356.png)

Make the following selections, and click on Save.

![Save](md-images/45cd4d0db11ad1ebfe32d148d7e63e0489486ef6342bbc1a8888efa0942a1fbc.png)  

Go to `Certificates & secrets` to add a new client secret, copy the value, and replace the `ClientSecret` setting in our `SecureWebApi`'s *appsettings.json* file.

![Client Secret](md-images/ee878d9693a213254c52dc5ec72b7e1c63aa34ab4e372680cdf5ce94471eef23.png)  

Go to `Expose an API`, click on `+ Add a scope`, and enter `access_as_user` for the `Scope name`, `Call the SecureWebAPI endpoints.` for the `Admin consent display name`, and `Allows the app to call the SecureWebAPI endpoints.` for the `Admin consent description`. Then keep `Enabled` checked, and click on `Add scope`.

![Expose an API](md-images/69a97bda4578983e8695c64e9c3b290185b977e2ac8c9cfcc35ad9643aed9eb1.png)  

Go to `API permissions`, click on `+ Add a permission`, then on `My APIs`, and select `MsalAuthInMaui`.

![My APIs](md-images/7e8542be816a3cde12ca0fffb4f6fc36d818589d9d6651b1be0b2a50e2573aa7.png)  

Then click on `Delegated permissions`, check `access_as_user`, and click `Add permissions`.

![Add permissions](md-images/98c9d6fd6f355d651071387896f876e6fe100e365f4d9c4720fc15f54cec48c8.png)  

Finally, go to `Branding & properties`, and get the `Publisher domain`, in our case `msalauthinmaui.onmicrosoft.com`, and update the `Domain` setting in the *appsettings.json* file of the `SecureWebApi` project.

Then for the `Instance` setting, also in *appsettings.json*, replace the `https://login.microsoftonline.com/` value we had in our previous demo, with `https://msalauthinmaui.b2clogin.com/`.

The complete file should look like below, but with your own IDs:

```json
{
  "AzureAd": {
    "Instance": "https://msalauthinmaui{YOUR-SUFFIX-HERE}.b2clogin.com/",
    "Domain": "msalauthinmaui.onmicrosoft.com",
    "TenantId": "REPLACE-WITH-YOUR-TENANT_ID",
    "ClientId": "REPLACE-WITH-YOUR-CLIENT_ID",
    "CallbackPath": "/signin-oidc",
    "Scopes": "access_as_user",
    "ClientSecret": "REPLACE-WITH-YOUR-CLIENT-SECRET",
    "ClientCertificates": [],
  },
  "MicrosoftGraph": {
    "BaseUrl": "https://graph.microsoft.com/v1.0",
    "Scopes": "user.read"
  },
  "DownstreamApi": {
    "BaseUrl": "REPLACE-WITH-YOUR-SECURE-API-URL",
    "Scopes": "user.read"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

#### Grant admin consent

Note that in the lower-left, you have not granted admin consent (also note that this graphic shows a different resource than yours)

![image-20220830122030647](md-images/image-20220830122030647.png)

Select `Grant admin consent for {YOUR-RESOURCE}` and then click `Yes` to confirm

#### Setup Twitter Identity Provider

Go back to the MsalAuthInMaui Azure B2C tenant, click on `Identity providers`, then on `Twitter`, and enter `Twitter` for the name, and paste the Client ID and Client Secret, which are the `API Key` and `API Key Secret` that we saved when we set up our app in the Twitter's `Developer Platform` portal.

![Twitter Identity Provider](md-images/015812162ee294f1da4d76fc8a0cf49a411168f542b60173efbe8e0d4c7cac80.png)  

>:point_up: The Client ID and Client Secret needed are not the OAuth 2.0 values we stored also, but the Twitter API Key and API Key Secret under the Consumer Keys section in the Twitter Developer Portal, Keys and Tokens section.

#### Create a User Flow

Now we need to create a `Sign up and sign in` user flow. Go to `User flows`, and click on `+ New user flow`.

![New user flow](md-images/106a8fc8d24a6c08e9bd4edd7780df7980a5c87d5a7da0c62bf8655d343a4db6.png)  

Here we can create a few different user flows, depending on the things we want to allow in our application. For now, we are only interested in the `Sign up and sign in` user flow, so click that, then keep the recommended version, and click on `Create`.

![Sign up and sign in](md-images/a016ee387ec9425c4ecda13045ff56f497aeaf5f79cb6da8f0c326cb2c132e78.png)  

Give it a name of `twitter_susi` to distinguish from other identity provider flows, for instance if we add support for `Google`, `Facebook`, etc. Enable `Email signup`, this will allow the users to create accounts with their own email, and password. Check the Twitter box under `Social identity providers`, and keep the Email, MFA enforcement defaults.

![twitter_susi](md-images/0160ca69deccffcdd579999fe6055fea6e2f16ed516f0e4b1cb1b669b62d85d8.png)  

>:point_up: Notice that the full name will be `B2C_1_twitter_susi`, and `B2C_1_` is pre-appended. This is important, as we are going to need the name of the flow in our MAUI application.

Check the attributes you want to collect when the users create an account with email and password, and any attributes you want to return in the access token. For our purposes, we are only going to select the `Display Name`, and keep the rest of the default values, (this selections can be changed later at any time.) Click on `Show more...`, in order to select `Display Name`, then click on `Ok`, and finally on `Create`.

![Display Name](md-images/bc38d01d864b88729da35eec0c2b1c3a4092628ab2d2a8d23d3278b32216cefc.png)  

![Twitter User Flow](md-images/aa8ca888daec69a9e882a7edbb85cdb1c2a15c36134984742c50558660a62eb9.png)  



### Re-Publish the SecureWeb API project

Because we've made changes to the configuration, this is a good time to re-publish the API project.

#### Test User Flow

You can test the user flow, by clicking on it, and then clicking on `Run user flow`.

![Test User Flow](md-images/3d3ef5ee595e08cee84c4d96e73a99864e45f2a8b2dec05fa34da14e6794715c.png)  

If everything is successfully configured, you should see a new tab, with the UI that eventually is going to show up in our MAUI app.

![Twitter Login](md-images/11702d7b364b1501bb713855c161936ff953e059b9adbd836b360dd1f94c81b3.png) 

Press the `Twitter` button and you should see something like this.

![Authorize Twitter](md-images/8350dcee9b498a93c42e2ff312de8247c5fa3b8246654a3dd9d03022577de786.png)  

You can now choose `Authorize app` or leave that step until later. The important thing is that you got this far.

Go back to the *appsettings.json* file in our SecureWebApi application, and add `"SignUpSignInPolicyId": "b2c_1_twitter_susi"` below `"ClientCertificates": [],`:

```json
  "AzureAd": {
    "Instance": "****************************,
    "Domain": "****************************",
    "TenantId": "****************************",
    "ClientId": "****************************",
    "CallbackPath": "/signin-oidc",
    "Scopes": "access_as_user",
    "ClientSecret": "****************************",
    "ClientCertificates": [],
    "SignUpSignInPolicyId": "b2c_1_twitter_susi"
  },
```

Right-click the SecureWebApi project, and publish the application.

![Right-click SecureWebApi](md-images/9e1b49b89a05263ce0e1c6629275645295af79f9800f2a2e30f87c30cfc66547.png)  

![Publish Application](md-images/da766bbf658b3d7c54b543c38e9e962073c93d6287efca548199b9990f82b9bf.png)  

### Add Twitter Authentication Support in MAUI

Now, it is time to take everything we put together, and finally add Twitter Authentication support in our MAUI application.

Since our `PCAWrapper` is going to change in the way we call `Azure AD B2C`, and to keep things separate, let's create an interface, and then create a new `PCASocialWrapper`

Duplicate the *PCAWrapper.cs* file, and name it *PCASocialWrapper.cs*, then rename the class, and constructor accordingly.

Then we are going to change our *PCASocialWrapper.cs* file to add support for social authentication flows.

Update the *IPCAWrapper.cs*, *PCAWrapper.cs*, and *PCASocialWrapper.cs* files to look like this:

#### *IPCAWrapper.cs*

```csharp
using Microsoft.Identity.Client;

namespace MsalAuthInMaui
{
    public interface IPCAWrapper
    {
        string[] Scopes { get; set; }
        Task<AuthenticationResult> AcquireTokenInteractiveAsync(string[] scopes);
        Task<AuthenticationResult> AcquireTokenSilentAsync(string[] scopes);
        Task SignOutAsync();
    }
}
```

#### *PCAWrapper.cs*

```csharp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using static System.Formats.Asn1.AsnWriter;

namespace MsalAuthInMaui
{
    /// <summary>
    /// This is a wrapper for PCA. It is singleton and can be utilized by both application and the MAM callback
    /// </summary>
    public class PCAWrapper : IPCAWrapper
    {
        private IConfiguration _configuration;
        private static Settings _settings { get; set; }

        internal IPublicClientApplication PCA { get; }

        internal bool UseEmbedded { get; set; } = false;
        public string[] Scopes { get; set; }

        // public constructor
        public PCAWrapper(IConfiguration configuration)
        {
            _configuration = configuration;
            _settings = _configuration.GetRequiredSection("Settings").Get<Settings>();
            Scopes = _settings.Scopes.ToStringArray();

            // Create PCA once. Make sure that all the config parameters below are passed
            PCA = PublicClientApplicationBuilder
                                        .Create(_settings.ClientId)
                                        .WithRedirectUri(PlatformConfig.Instance.RedirectUri)
                                        .WithIosKeychainSecurityGroup("com.microsoft.adalcache")
                                        .Build();
        }

        /// <summary>
        /// Acquire the token silently
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string[] scopes)
        {
            var accts = await PCA.GetAccountsAsync().ConfigureAwait(false);
            var acct = accts.FirstOrDefault();

            var authResult = await PCA.AcquireTokenSilent(scopes, acct)
                                        .ExecuteAsync().ConfigureAwait(false);
            return authResult;

        }

        /// <summary>
        /// Perform the interactive acquisition of the token for the given scope
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenInteractiveAsync(string[] scopes)
        {
            var systemWebViewOptions = new SystemWebViewOptions();
#if IOS
            // embedded view is not supported on Android
            if (UseEmbedded)
            {

                return await PCA.AcquireTokenInteractive(scopes)
                                        .WithUseEmbeddedWebView(true)
                                        .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                        .ExecuteAsync()
                                        .ConfigureAwait(false);
            }

            // Hide the privacy prompt in iOS
            systemWebViewOptions.iOSHidePrivacyPrompt = true;
#endif

            return await PCA.AcquireTokenInteractive(scopes)
                                    .WithAuthority(_settings.Authority)
                                    .WithTenantId(_settings.TenantId)
                                    .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                    .WithUseEmbeddedWebView(true)
                                    .ExecuteAsync()
                                    .ConfigureAwait(false);
        }

        /// <summary>
        /// Signout may not perform the complete signout as company portal may hold
        /// the token.
        /// </summary>
        /// <returns></returns>
        public async Task SignOutAsync()
        {
            var accounts = await PCA.GetAccountsAsync().ConfigureAwait(false);
            foreach (var acct in accounts)
            {
                await PCA.RemoveAsync(acct).ConfigureAwait(false);
            }
        }
    }
}
```

#### *PCASocialWrapper.cs*

Ignore compiler errors for now.

```csharp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using static System.Formats.Asn1.AsnWriter;

namespace MsalAuthInMaui
{
    /// <summary>
    /// This is a wrapper for PCA. It is singleton and can be utilized by both application and the MAM callback
    /// </summary>
    public class PCASocialWrapper : IPCAWrapper
    {
        private IConfiguration _configuration;
        private static Settings _settings { get; set; }

        internal IPublicClientApplication PCA { get; }

        internal bool UseEmbedded { get; set; } = false;
        public string[] Scopes { get; set; }

        // public constructor
        public PCASocialWrapper(IConfiguration configuration)
        {
            _configuration = configuration;
            _settings = _configuration.GetRequiredSection("Settings").Get<Settings>();
            Scopes = _settings.ScopesForTwitter.ToStringArray();

            // Create PCA once. Make sure that all the config parameters below are passed
            PCA = PublicClientApplicationBuilder
                                        .Create(_settings.ClientIdForTwitter)
                                        .WithB2CAuthority(_settings.AuthorityForTwitter)
                                        .WithRedirectUri(PlatformConfig.Instance.RedirectUri)
                                        .WithIosKeychainSecurityGroup("com.microsoft.adalcache")
                                        .Build();
        }

        /// <summary>
        /// Acquire the token silently
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns>Authentication result</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string[] scopes)
        {
            var accts = await PCA.GetAccountsAsync(_settings.PolicySignUpSignInForTwitter).ConfigureAwait(false);
            var acct = accts.FirstOrDefault();

            var authResult = await PCA.AcquireTokenSilent(scopes, acct)
                                        .ExecuteAsync().ConfigureAwait(false);
            return authResult;

        }

        /// <summary>
        /// Perform the interactive acquisition of the token for the given scope
        /// </summary>
        /// <param name="scopes">desired scopes</param>
        /// <returns></returns>
        public async Task<AuthenticationResult> AcquireTokenInteractiveAsync(string[] scopes)
        {
            var systemWebViewOptions = new SystemWebViewOptions();
#if IOS
            // embedded view is not supported on Android
            if (UseEmbedded)
            {

                return await PCA.AcquireTokenInteractive(scopes)
                                        .WithUseEmbeddedWebView(true)
                                        .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                        .ExecuteAsync()
                                        .ConfigureAwait(false);
            }

            // Hide the privacy prompt in iOS
            systemWebViewOptions.iOSHidePrivacyPrompt = true;
#endif

            var accounts = await PCA.GetAccountsAsync(_settings.PolicySignUpSignInForTwitter).ConfigureAwait(false); ;
            var acct = accounts.FirstOrDefault();

            return await PCA.AcquireTokenInteractive(scopes)
                                    .WithB2CAuthority(_settings.AuthorityForTwitter)
                                    .WithAccount(accounts.FirstOrDefault())
                                    .WithParentActivityOrWindow(PlatformConfig.Instance.ParentWindow)
                                    .WithUseEmbeddedWebView(true)
                                    .ExecuteAsync()
                                    .ConfigureAwait(false);
        }

        /// <summary>
        /// Signout may not perform the complete signout as company portal may hold
        /// the token.
        /// </summary>
        /// <returns></returns>
        public async Task SignOutAsync()
        {
            var accounts = await PCA.GetAccountsAsync().ConfigureAwait(false);
            foreach (var acct in accounts)
            {
                await PCA.RemoveAsync(acct).ConfigureAwait(false);
            }
        }
    }
}
```

Open the *MainPage.xaml* file, and add a Login With Twitter button.

```xaml
<?xml version="1.0" encoding="utf-8" ?>
<ContentPage xmlns="http://schemas.microsoft.com/dotnet/2021/maui"
			 xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
			 x:Class="MsalAuthInMaui.MainPage">

    <ScrollView>
        <VerticalStackLayout Spacing="25"
							 Padding="30,0"
							 VerticalOptions="Center">

            <Image Source="dotnet_bot.png"
				   SemanticProperties.Description="Cute dot net bot waving hi to you!"
				   HeightRequest="200"
				   HorizontalOptions="Center" />

            <Label Text="Hello, World!"
				   SemanticProperties.HeadingLevel="Level1"
				   FontSize="32"
				   HorizontalOptions="Center" />

            <Label Text="Welcome to .NET Multi-platform App UI"
				   SemanticProperties.HeadingLevel="Level2"
				   SemanticProperties.Description="Welcome to dot net Multi platform App U I"
				   FontSize="18"
				   HorizontalOptions="Center" />

            <HorizontalStackLayout 
				HorizontalOptions="Center">
                <Button x:Name="LoginButton"
						Text="Log in (MS)"
						SemanticProperties.Hint="Log in"
						Clicked="OnLoginButtonClicked"
						HorizontalOptions="Center"
						Margin="8,0,8,0" />

                <Button x:Name="LogoutButton"
						Text="Log out"
						SemanticProperties.Hint="Log out"
						Clicked="OnLogoutButtonClicked"
						HorizontalOptions="Center"
						Margin="8,0,8,0" />
            </HorizontalStackLayout>


            <Label Text="Login with your social account"
				   SemanticProperties.HeadingLevel="Level1"
				   FontSize="18"
				   HorizontalOptions="Center" />

            <HorizontalStackLayout HorizontalOptions="Center">
                <Button x:Name="LoginWithTwitterButton"
						Text="Login (Social)"
						SemanticProperties.Hint="Log in with Twitter"
						Clicked="OnLoginWithTwitterButtonClicked"
						HorizontalOptions="Center"
						Margin="8,0,8,0" />
            </HorizontalStackLayout>

            <Button x:Name="GetWeatherForecastButton"
					Text="Get Weather Forecast"
					SemanticProperties.Hint="Get weather forecast data"
					Clicked="OnGetWeatherForecastButtonClicked"
					HorizontalOptions="Center"
					IsEnabled="{Binding IsLoggedIn}"/>
        </VerticalStackLayout>
    </ScrollView>

</ContentPage>
```

Finally, update the *MainPage.xaml.cs* file to look like this. Note that you have to change the placeholder for your API url.

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

namespace MsalAuthInMaui
{
    public partial class MainPage : ContentPage
    {
        private string _accessToken = string.Empty;
        private PCAWrapper _pcaWrapper;
        private PCASocialWrapper _pcaSocialWrapper;
        private IConfiguration _configuration;

        bool _isLoggedIn = false;
        public bool IsLoggedIn
        {
            get => _isLoggedIn;
            set
            {
                if (value == _isLoggedIn) return;
                _isLoggedIn = value;
                OnPropertyChanged(nameof(IsLoggedIn));
            }
        }

        public MainPage(IConfiguration configuration)
        {
            _configuration = configuration;
            _pcaWrapper = new PCAWrapper(_configuration);
            _pcaSocialWrapper = new PCASocialWrapper(_configuration);
            BindingContext = this;
            InitializeComponent();
            _ = Login(_pcaWrapper);
        }

        async private void OnLoginButtonClicked(object sender, EventArgs e)
        {
            await Login(_pcaWrapper).ConfigureAwait(false);
        }

        async private void OnLoginWithTwitterButtonClicked(object sender, EventArgs e)
        {
            await Login(_pcaSocialWrapper).ConfigureAwait(false);
        }

        private async Task Login(IPCAWrapper pcaWrapper)
        {
            try
            {
                // Attempt silent login, and obtain access token.
                var result = await pcaWrapper.AcquireTokenSilentAsync(pcaWrapper.Scopes).ConfigureAwait(false);
                IsLoggedIn = true;

                // Set access token.
                _accessToken = result.AccessToken;

                // Display Access Token from AcquireTokenSilentAsync call.
                await ShowOkMessage("Access Token from AcquireTokenSilentAsync call", _accessToken).ConfigureAwait(false);
            }
            // A MsalUiRequiredException will be thrown, if this is the first attempt to login, or after logging out.
            catch (MsalUiRequiredException)
            {
                try
                {
                    // Perform interactive login, and obtain access token.
                    var result = await pcaWrapper.AcquireTokenInteractiveAsync(pcaWrapper.Scopes).ConfigureAwait(false);
                    IsLoggedIn = true;

                    // Set access token.
                    _accessToken = result.AccessToken;

                    // Display Access Token from AcquireTokenInteractiveAsync call.
                    await ShowOkMessage("Access Token from AcquireTokenInteractiveAsync call", _accessToken).ConfigureAwait(false);
                }
                catch
                {
                    // Ignore.
                }
            }
            catch (Exception ex)
            {
                IsLoggedIn = false;
                await ShowOkMessage("Exception in AcquireTokenSilentAsync", ex.Message).ConfigureAwait(false);
            }
        }

        async private void OnLogoutButtonClicked(object sender, EventArgs e)
        {
            // Log out from Microsoft.
            await _pcaWrapper.SignOutAsync().ConfigureAwait(false);

            // Log out from Social.
            await _pcaSocialWrapper.SignOutAsync().ConfigureAwait(false);

            await ShowOkMessage("Signed Out", "Sign out complete.").ConfigureAwait(false);
            IsLoggedIn = false;
            _accessToken = string.Empty;
        }

        async private void OnGetWeatherForecastButtonClicked(object sender, EventArgs e)
        {
            // Call the Secure Web API to get the weatherforecast data.
            var weatherForecastData = await CallSecureWebApi(_accessToken).ConfigureAwait(false);

            // Show the data.
            if (weatherForecastData != string.Empty)
                await ShowOkMessage("WeatherForecast data", weatherForecastData).ConfigureAwait(false);
        }

        // Call the Secure Web API.
        private static async Task<string> CallSecureWebApi(string accessToken)
        {
            if (accessToken == string.Empty)
                return string.Empty;

            try
            {
                // Get the weather forecast data from the Secure Web API.
                var client = new HttpClient();

                // Create the request.
                var message = new HttpRequestMessage(HttpMethod.Get, "{REPLACE-WITH-API-URL}/weatherforecast");

                // Add the Authorization Bearer header.
                message.Headers.Add("Authorization", $"Bearer {accessToken}");

                // Send the request.
                var response = await client.SendAsync(message).ConfigureAwait(false);

                // Get the response.
                var responseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Ensure a success status code.
                response.EnsureSuccessStatusCode();

                // Return the response.
                return responseString;
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }

        private Task ShowOkMessage(string title, string message)
        {
            _ = Dispatcher.Dispatch(async () =>
            {
                await DisplayAlert(title, message, "OK").ConfigureAwait(false);
            });
            return Task.CompletedTask;
        }
    }
}
```

Now, update the *Settings.cs* file to add the new Twitter settings.

```csharp
namespace MsalAuthInMaui
{
    public class Settings
    {
        // Azure AD B2C Microsoft Authentication
        public string ClientId { get; set; } = null;
        public string TenantId { get; set; } = null;
        public string Authority { get; set; } = null;
        public NestedSettings[] Scopes { get; set; } = null;

        // Azure AD B2C Twitter Authentication
        public string ClientIdForTwitter { get; set; } = null;
        public string TenantForTwitter { get; set; } = null;
        public string TenantIdForTwitter { get; set; } = null;
        public string InstanceUrlForTwitter { get; set; } = null;
        public string PolicySignUpSignInForTwitter { get; set; } = null;
        public string AuthorityForTwitter { get; set; } = null;
        public NestedSettings[] ScopesForTwitter { get; set; } = null;
    }
}
```

And finally, update the *appsettings.json* file to add the new Twitter settings as well. 

```json
{
  "Settings": {
    "ClientId": "{REPLACE-WITH-YOUR-CLIENT-ID}",
    "TenantId": "{REPLACE-WITH-YOUR-TENANT-ID}",
    "Authority": "https://login.microsoftonline.com/{REPLACE-WITH-YOUR-TENANT-ID}",
    "Scopes": [
      { "Value": "api://{REPLACE-WITH-YOUR-CLIENT-ID}/access_as_user" }
    ],
    "ClientIdForTwitter": "{REPLACE-WITH-YOUR-CLIENT-ID}",
    "TenantForTwitter": "msalauthinmaui{YOUR-SUFFIX-HERE}.onmicrosoft.com",
    "TenantIdForTwitter": "{REPLACE-WITH-YOUR-TENANT-ID}",
    "InstanceUrlForTwitter": "https://msalauthinmaui{YOUR-SUFFIX-HERE}.b2clogin.com",
    "PolicySignUpSignInForTwitter": "b2c_1_twitter_susi",
    "AuthorityForTwitter": "https://msalauthinmaui{YOUR-SUFFIX-HERE}.b2clogin.com/tfp/msalauthinmaui{YOUR-SUFFIX-HERE}.onmicrosoft.com/b2c_1_twitter_susi",
    "ScopesForTwitter": [
      { "Value": "https://msalauthinmaui{YOUR-SUFFIX-HERE}.onmicrosoft.com/{REPLACE-WITH-YOUR-CLIENT-ID}/access_as_user" }
    ]
  }
}
```

>:point_up: Make sure you update the settings with your own values.

Run the MAUI app, and try login in with Twitter, and get the Weather Forecast data.

First we are going to login with Twitter, then we are going to create a new account using any email, and setting your password, and account name. Then we are going to log in with that new account.

#### Sign in with Twitter

Click Twitter in the app, and Twitter again in the `Azure AD B2C` `Sign in` screen, to log in with your Twitter account.

<img src="md-images/image-20220830135805571-166188406360341.png" alt="image-20220830135805571" style="zoom:50%;" />

<img src="md-images/image-20220830135837403-166188406360342.png" alt="image-20220830135837403" style="zoom:50%;" />

<img src="md-images/image-20220830135900178-166188406360343.png" alt="image-20220830135900178" style="zoom:50%;" />

<img src="md-images/image-20220830135913088-166188406360344.png" alt="image-20220830135913088" style="zoom:50%;" />

<img src="md-images/image-20220830135939196-166188406360345.png" alt="image-20220830135939196" style="zoom:50%;" />

<img src="md-images/image-20220830135955044-166188406360346.png" alt="image-20220830135955044" style="zoom:50%;" />

#### Create an Account with Email

In order to create a new account, first log out, then click the `Login {social)` button, and then `Sign up now` in the `Azure AD B2C` `Sign in` screen.

<img src="md-images/image-20220830140238239-166188406360348.png" alt="image-20220830140238239" style="zoom:50%;" />

<img src="md-images/image-20220830140331813-166188406360347.png" alt="image-20220830140331813" style="zoom:50%;" />

Enter your email address and click the `Send verification code` button.

<img src="md-images/image-20220830140412624-166188406360349.png" alt="image-20220830140412624" style="zoom:50%;" />

Check your inbox for the authentication code

![Verification Code Email](md-images/52a68093fa31373f6491e2f2ffd50d389b188bee2cb9ca324657cf66f92772e3.png)

Enter the code in the app and click the `Verify code` button. 

<img src="md-images/image-20220830140612564-166188406360350.png" alt="image-20220830140612564" style="zoom:50%;" />

You can then enter a new password, confirm it, and enter your Display Name. Then click the `Create` button.

<img src="md-images/image-20220830141105088-166188406360351.png" alt="image-20220830141105088" style="zoom:50%;" />



Notice how we were able to login with our new local account, and call the SecureWebApi to get the data.

### Verify Accounts

Go back to your Azure AD B2C instance, and click on `Users`.

Notice the both the Twitter account, as well as the email-based account show up in Azure.

![image-20220830141323575](md-images/image-20220830141323575-166188406360452.png)

### Summary

In this episode, we added social authorization support to the [MsalAuthInMaui](https://github.com/carlfranklin/MsalAuthInMaui) repo we built in the last episode.

We enhanced the repo by moving out hard-coded settings, to an *appsettings.json* file.

Finally, we configured our MAUI application, to login with Twitter, or by creating a new account.

For more information about .NET MAUI, Azure AD B2C Identity providers, and Twitter OAuth Authentication, check the links in the resources section below.

## Complete Code

The complete code for this demo can be found in the link below.

- <https://github.com/carlfranklin/MsalSocialAuthInMaui>

## Resources

| Resource Title                                               | Url                                                          |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| The .NET Show with Carl Franklin                             | <https://thedotnetshow.com>                                  |
| Download .NET                                                | <https://dotnet.microsoft.com/en-us/download>                |
| .NET Multi-platform App UI documentation                     | <https://docs.microsoft.com/en-us/dotnet/maui/>              |
| App Configuration Settings in .NET MAUI (appsettings.json)   | <https://montemagno.com/dotnet-maui-appsettings-json-configuration/> |
| Microsoft identity platform code samples                     | <https://docs.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code> |
| Tutorial: Create an Azure Active Directory B2C tenant        | <https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-tenant?WT.mc_id=Portal-Microsoft_AAD_B2CAdmin> |
| Set up sign-up and sign-in with a Twitter account using Azure Active Directory B2C | <https://docs.microsoft.com/en-us/azure/active-directory-b2c/identity-provider-twitter?WT.mc_id=Portal-Microsoft_AAD_B2CAdmin&pivots=b2c-user-flow> |
| AAD B2C specifics                                            | <https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/AAD-B2C-specifics> |
