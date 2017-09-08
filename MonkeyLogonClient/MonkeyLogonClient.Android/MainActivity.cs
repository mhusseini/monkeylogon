using Android.App;
using Android.OS;
using Android.Views;
using Android.Widget;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using Android.Content;
using Xamarin.Auth;

namespace MonkeyLogonClient.Droid
{
    [Activity(Label = "MonkeyLogonClient.Android", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : Activity
    {
        private Button button;
        private ListView listView;

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            this.SetContentView(Resource.Layout.Main);

            this.button = this.FindViewById<Button>(Resource.Id.button1);
            this.listView = this.FindViewById<ListView>(Resource.Id.listView1);

            this.button.Click += this.Logon;
        }

        private void Logon(object sender, EventArgs _)
        {
            // install Xamarin.Auth package
            var authenticator = new OAuth2Authenticator(
                clientId: "monkeylogonclient",
                scope: "profile",
                authorizeUrl: new Uri("https://192.168.179.25:50163/account/authorize"),
                redirectUrl: new Uri("com.example.mhuss.monkeylogon:/oauth2redirect"),
                isUsingNativeUI: true)
            {
                AllowCancel = true,
                IsLoadableRedirectUri = true
            };

            authenticator.Completed += (__, e) => this.OnLoggedOn(e);

            ActivityCustomUrlSchemeInterceptor.Authenticator = authenticator;
            var intent = authenticator.GetUI(Application.Context);
            intent.SetFlags(ActivityFlags.NewTask);
            Application.Context.StartActivity(intent);
        }

        private async void OnLoggedOn(AuthenticatorCompletedEventArgs e)
        {
            if (!e.IsAuthenticated)
            {
                return;
            }

            var authToken = e.Account.Properties["access_token"];
            var httpClient = new HttpClient(new BypassSslValidationClientHandler());
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
            var json = await httpClient.GetStringAsync(new Uri("https://192.168.179.25:50163/api/Banana"));
            var bananas = JsonConvert.DeserializeObject<string[]>(json);

            this.button.Visibility = ViewStates.Gone;
            this.listView.Adapter = new ArrayAdapter<string>(this, Resource.Layout.BananaListItem, Resource.Id.textView1, bananas);
        }
    }
}