using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NanoAuth.Data;
using NanoAuth.Data.Identity;
using NanoAuth.Extensions;
using NanoAuth.Services;
using NanoAuth.Settings;
using NanoAuth.Settings.Google;
using System.IO;
using Microsoft.AspNetCore.HttpOverrides;
using NanoAuth.Services.Google;

namespace NanoAuth
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
            services.ConfigureSettings<MailgunSettings>(Configuration.GetSection("Mailgun"));
            services.ConfigureSettings<ReCaptchaSettings>(Configuration.GetSection("Google:reCaptcha"));
            services.AddTransient<IReCaptchaService, ReCaptchaService>();

            services.AddHttpContextAccessor();

            services.AddDbContext<NanoDbContext>(options =>
                options.UseSqlite(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<NanoUser, NanoRole>(options => options.SignIn.RequireConfirmedAccount = true) // TODO: Increase security
                .AddEntityFrameworkStores<NanoDbContext>()
                .AddDefaultTokenProviders();

            var contentRoot = Configuration.GetValue<string>(WebHostDefaults.ContentRootKey);
            var configFolder = Path.Combine(contentRoot, "Config");

            var resManager =
                new IdentityServerResourceManager(configFolder);

            services.AddControllersWithViews();

            var builder = services
                .AddIdentityServer(options =>
                {
                    options.Events.RaiseErrorEvents =
                        options.Events.RaiseFailureEvents =
                            options.Events.RaiseInformationEvents =
                                options.Events.RaiseSuccessEvents = true;
                })
                .AddInMemoryIdentityResources(resManager.LoadIdentityResources())
                .AddInMemoryApiResources(resManager.LoadApiResources())
                .AddInMemoryClients(resManager.LoadClients())
                .AddAspNetIdentity<NanoUser>()
                .AddOperationalStore<NanoDbContext>(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseSqlite(Configuration.GetConnectionString("DefaultConnection"),
                            optionsBuilder =>
                                optionsBuilder.MigrationsAssembly(typeof(Startup).Assembly.GetName()
                                    .Name));
                })
                .AddInMemoryCaching()

                .AddDeveloperSigningCredential();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                //app.UseHsts();
            }

            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
