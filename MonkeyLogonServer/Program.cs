using System.IO;
using System.Linq;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace MonkeyLogon
{
    public class Program
    {
        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseKestrel(options =>
                {
                    foreach (var ipAddress in from address in Dns.GetHostEntry(Dns.GetHostName()).AddressList
                                              where address.AddressFamily == AddressFamily.InterNetwork
                                              select address)
                    {
                        options.Listen(ipAddress, 50162);
                        options.Listen(ipAddress, 50163, listenOptions =>
                            listenOptions.UseHttps(new X509Certificate2("monkeylogon.pfx", ""))
                        );
                    }
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