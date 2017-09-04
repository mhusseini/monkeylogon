using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace MonkeyLogon
{
    public static class ApplicationInfo
    {
        public const string AppName = "monkeylogon";
        public const int HttpPort = 50162;
        public const int HttpsPort = 50163;

        public static readonly IPAddress IpAddress = Dns.GetHostEntry(Dns.GetHostName())
            .AddressList
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

        public static string GetUrl() => $"https://{IpAddress}:{HttpsPort}/";
    }
}