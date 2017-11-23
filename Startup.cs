using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SlackIntegration.Data;
using SlackIntegration.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Authentication;

namespace SlackIntegration
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            services.AddAuthentication().AddCookie("SlackCookies", options =>
            {
                options.LoginPath = "/Account/LogIn";
                options.LogoutPath = "/Account/LogOut";
            }).AddOAuth(
                "Slack", o =>
                {
                    o.ClientId = Configuration["Slack:ClientId"];
                    o.ClientSecret = Configuration["Slack:ClientSecret"];
                    o.CallbackPath = new PathString("/signin-slack");
                    o.AuthorizationEndpoint = "https://slack.com/oauth/authorize";
                    o.TokenEndpoint = "https://slack.com/api/oauth.access";
                    o.UserInformationEndpoint = "https://slack.com/api/users.identity?token=";
                    o.Scope.Add("identity.basic");
                    o.Events = new OAuthEvents
                    {
                        OnCreatingTicket = async context =>
                        {
                            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint + context.AccessToken);
                            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                            response.EnsureSuccessStatusCode();
                            var userObject = JObject.Parse(await response.Content.ReadAsStringAsync());
                            var user = userObject.SelectToken("user");
                            var userId = user.Value<string>("id");
                            if (!string.IsNullOrEmpty(userId))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                            }
                            var fullName = user.Value<string>("name");
                            if (!string.IsNullOrEmpty(fullName))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.Name, fullName, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                            }
                        }
                    };
                });

            services.AddMvc()
                .AddRazorPagesOptions(options =>
                {
                    options.Conventions.AuthorizeFolder("/Account/Manage");
                    options.Conventions.AuthorizePage("/Account/Logout");
                });

            // Register no-op EmailSender used by account confirmation and password reset during development
            // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=532713
            services.AddSingleton<IEmailSender, EmailSender>();
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
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();
            app.Map("/login", builder =>
            {
                builder.Run(async context =>
                {
                    await context.ChallengeAsync("Slack",
                        properties: new AuthenticationProperties() { RedirectUri = "/" });
                });
            });

            app.Map("/logout", builder =>
            {
                builder.Run(async context =>
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/");
                });
            });
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }
    }
}
