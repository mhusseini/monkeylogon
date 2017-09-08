using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using MonkeyLogon.Data;
using OpenIddict.Core;
using OpenIddict.Models;

namespace MonkeyLogon
{
    public class OpenIdDictInitializer
    {
        public static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken)
        {
            // Create a new service scope to ensure the database context is correctly disposed when this methods returns.
            using (var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                await context.Database.EnsureCreatedAsync(cancellationToken);

                var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

                if (await manager.FindByClientIdAsync("monkeylogonclient", cancellationToken) == null)
                {
                    var application = new OpenIddictApplication
                    {
                        ClientId = "monkeylogonclient",
                        DisplayName = "MonkeyLogon Client",
                        Type = "public",
                        RedirectUri = "com.example.mhuss.monkeylogon:/oauth2redirect"
                    };

                    await manager.CreateAsync(application, cancellationToken);
                }

                if (await manager.FindByClientIdAsync("browser-test", cancellationToken) == null)
                {
                    var application = new OpenIddictApplication
                    {
                        ClientId = "browser-test",
                        DisplayName = "browser-test",
                        Type = "public",
                        RedirectUri = "http://localhost"
                    };

                    await manager.CreateAsync(application, cancellationToken);
                }
            }
        }
    }
}