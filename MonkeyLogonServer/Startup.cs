using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using MonkeyLogon.Data;
using MonkeyLogon.Models;
using MonkeyLogon.Services;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace MonkeyLogon
{
    public class Startup
    {
        private readonly IHostingEnvironment environment;

        public Startup(IHostingEnvironment env)
        {
            this.environment = env;

            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                builder.AddUserSecrets<Startup>();
            }

            this.Configuration = builder.Build();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IServiceProvider serviceProvider)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMiddleware<RequestReconstructionMiddleWare>(serviceProvider.GetService<IDataProtectionProvider>());

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            OpenIdDictInitializer.InitializeAsync(app.ApplicationServices, CancellationToken.None).GetAwaiter().GetResult();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDataProtection()
                .SetApplicationName(ApplicationInfo.AppName)
                .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(this.environment.ContentRootPath, @"keys")))
                .DisableAutomaticKeyGeneration();

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(this.Configuration.GetConnectionString("DefaultConnection"));
                options.UseOpenIddict();
            });

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var cert = new X509Certificate2(Path.Combine(this.environment.ContentRootPath, "monkeylogon.pfx"), "");

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();

            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });

            services.AddOpenIddict(options =>
            {
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>()
                    .AddMvcBinders()
                    .EnableAuthorizationEndpoint("/account/authorize")
                    .EnableLogoutEndpoint("/account/logout")
                    .EnableUserinfoEndpoint("/api/me")
                    .AllowImplicitFlow()
                    .UseJsonWebTokens()
                    .AddSigningCertificate(cert);

                if (this.environment.IsDevelopment())
                {
                    options.DisableHttpsRequirement();
                    options.AddEphemeralSigningKey();
                }
            });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.Audience = ApplicationInfo.AppName;
                    options.ClaimsIssuer = ApplicationInfo.AppName;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = OpenIdConnectConstants.Claims.Name,
                        RoleClaimType = OpenIdConnectConstants.Claims.Role,
                        ValidAudience = ApplicationInfo.AppName,
                        ValidIssuer = ApplicationInfo.GetUrl(),
                        IssuerSigningKey = new RsaSecurityKey(cert.GetRSAPrivateKey().ExportParameters(false))
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Request.Path.Value.StartsWith("/api"))
                            {
                                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            }

                            return Task.CompletedTask;
                        }
                    };
                })
                .AddMicrosoftAccount(options =>
                {
                    options.ClientId = this.Configuration["MicrosoftClientId"];
                    options.ClientSecret = this.Configuration["MicrosoftClientSecret"];
                })
                .AddGoogle(options =>
                {
                    options.ClientId = this.Configuration["GoogleClientId"];
                    options.ClientSecret = this.Configuration["GoogleClientSecret"];
                });

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();

            services.AddMvc();
        }
    }
}