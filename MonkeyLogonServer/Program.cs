using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace MonkeyLogon
{
    public class Program
    {
        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseKestrel(options =>
                {
                    options.Listen(ApplicationInfo.IpAddress, ApplicationInfo.HttpPort);
                    options.Listen(ApplicationInfo.IpAddress, ApplicationInfo.HttpsPort, listenOptions =>
                        listenOptions.UseHttps(new X509Certificate2("monkeylogon.pfx", ""))
                    );

                    options.Listen(IPAddress.Loopback, ApplicationInfo.HttpPort);
                    options.Listen(IPAddress.Loopback, ApplicationInfo.HttpsPort, listenOptions =>
                        listenOptions.UseHttps(new X509Certificate2("monkeylogon.pfx", ""))
                    );
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .Build();

        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }
    }
}