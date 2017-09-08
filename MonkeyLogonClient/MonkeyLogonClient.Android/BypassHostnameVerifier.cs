using Javax.Net.Ssl;

namespace MonkeyLogonClient.Droid
{
    internal class BypassHostnameVerifier : Java.Lang.Object, IHostnameVerifier
    {
        public bool Verify(string hostname, ISSLSession session)
        {
            return true;
        }
    }
}