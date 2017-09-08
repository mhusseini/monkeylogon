using Android.App;
using Android.Content;
using Android.OS;
using Xamarin.Auth;

namespace MonkeyLogonClient.Droid
{
    [Activity(Label = "ActivityCustomUrlSchemeInterceptor")]
    [
        IntentFilter
        (
            new[] { Intent.ActionView },
            Categories = new[]
            {
                Intent.CategoryDefault,
                Intent.CategoryBrowsable
            },
            DataScheme = IntentFilterDataScheme,
            DataPath = IntentFilterDataPath
        )
    ]
    public class ActivityCustomUrlSchemeInterceptor : Activity
    {
        internal const string IntentFilterDataPath = "/oauth2redirect";
        internal const string IntentFilterDataScheme = "com.example.mhuss.monkeylogon";
        public static OAuth2Authenticator Authenticator { get; set; }

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            if (Authenticator != null)
            {
                var uriAndroid = this.Intent.Data;
                var uriNetfx = new System.Uri(uriAndroid.ToString());
                Authenticator.OnPageLoading(uriNetfx);
            }

            this.Finish();
        }
    }
}