using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using MonkeyLogon.Data;
using MonkeyLogon.Models;
using MonkeyLogon.Services;
using OpenIddict.Core;

namespace MonkeyLogon
{
    public class Startup
    {
        private IHostingEnvironment env;

        public Startup(IHostingEnvironment env)
        {
            this.env = env;

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

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(this.Configuration.GetConnectionString("DefaultConnection"));
                options.UseOpenIddict();
            });

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var cert = new X509Certificate2(Path.Combine(this.env.ContentRootPath, "monkeylogon.pfx"), "");

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();

            services.AddOpenIddict(options =>
            {
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();
                options.AddMvcBinders();
                options.EnableAuthorizationEndpoint("/account/apilogin")
                    .EnableLogoutEndpoint("/account/logout")
                    .EnableUserinfoEndpoint("/api/me");
                options.AllowImplicitFlow();
                options.UseJsonWebTokens();
                options.AddSigningCertificate(cert);

                if (this.env.IsDevelopment())
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
                    options.Audience = "monkeylogon";
                    options.ClaimsIssuer = "monkeylogon";
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = OpenIdConnectConstants.Claims.Name,
                        RoleClaimType = OpenIdConnectConstants.Claims.Role,
                        ValidAudience = "monkeylogon",
                        ValidIssuer = "monkeylogon",
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

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
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

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
