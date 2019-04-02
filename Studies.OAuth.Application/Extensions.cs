using Owin;
using System;
using System.Linq;
using System.Text;
using Microsoft.Owin;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Owin.Security.OAuth;
using Studies.OAuth.Application.Auth;

namespace Studies.OAuth.Application
{
    public static class Extensions
    { 
        public static void ConfigureOAuth(this IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(1),
                Provider = new AuthorizationServerProvider()
            };

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}