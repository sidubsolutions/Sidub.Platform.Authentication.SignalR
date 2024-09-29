/*
 * Sidub Platform - Authentication - SignalR
 * Copyright (C) 2024 Sidub Inc.
 * All rights reserved.
 *
 * This file is part of Sidub Platform - Authentication - SignalR (the "Product").
 *
 * The Product is dual-licensed under:
 * 1. The GNU Affero General Public License version 3 (AGPLv3)
 * 2. Sidub Inc.'s Proprietary Software License Agreement (PSLA)
 *
 * You may choose to use, redistribute, and/or modify the Product under
 * the terms of either license.
 *
 * The Product is provided "AS IS" and "AS AVAILABLE," without any
 * warranties or conditions of any kind, either express or implied, including
 * but not limited to implied warranties or conditions of merchantability and
 * fitness for a particular purpose. See the applicable license for more
 * details.
 *
 * See the LICENSE.txt file for detailed license terms and conditions or
 * visit https://sidub.ca/licensing for a copy of the license texts.
 */

#region Imports

using Azure.Core;
using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using Sidub.Platform.Authentication.Credentials;
using Sidub.Platform.Core;
using Sidub.Platform.Core.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

#endregion

namespace Sidub.Platform.Authentication.Handlers
{

    /// <summary>
    /// Handles authentication for SignalR hubs (HubConnectionBuilder).
    /// </summary>
    public class HubConnectionBuilderAuthenticationHandler : IAuthenticationHandler<IHubConnectionBuilder>
    {

        #region Member variables

        private readonly IServiceRegistry _serviceRegistry;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="HubConnectionBuilderAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="serviceRegistry">The service registry.</param>
        public HubConnectionBuilderAuthenticationHandler(IServiceRegistry serviceRegistry)
        {
            _serviceRegistry = serviceRegistry;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Handles the authentication for HubConnectionBuilder.
        /// </summary>
        /// <param name="ServiceReferenceContext">The service reference context.</param>
        /// <param name="request">The HubConnectionBuilder instance.</param>
        /// <returns>The authenticated HubConnectionBuilder instance.</returns>
        public IHubConnectionBuilder Handle(ServiceReference ServiceReferenceContext, IHubConnectionBuilder request)
        {
            // check if authentication exists for given ServiceReference...
            var credential = _serviceRegistry.GetMetadata<IClientCredential>(ServiceReferenceContext).SingleOrDefault();

            // if no credentials exist, exit...
            if (credential is null)
                return request;

            // handle credentials based on type...
            switch (credential)
            {
                case UserTokenCredential userTokenAcquisition:
                    request.Services.Configure<HttpConnectionOptions>(options =>
                    {
                        options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                        options.AccessTokenProvider = async () =>
                        {
                            var tokenAcquisition = userTokenAcquisition.TokenAcquisition;
                            var scope = userTokenAcquisition.Scope;

                            var bearer = await tokenAcquisition.GetAccessTokenForUserAsync(new[] { scope }, null, user: userTokenAcquisition.ClaimsPrincipal);

                            return bearer;
                        };
                    });

                    return request;

                case GenericUserCredential genericUser:
                    request.Services.Configure<HttpConnectionOptions>(options =>
                    {
                        options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                        options.AccessTokenProvider = async () =>
                        {
                            var tokenHandler = new JwtSecurityTokenHandler();
                            //var key = Encoding.ASCII.GetBytes(_configuration["Jwt:key"]);
                            var tokenDescriptor = new SecurityTokenDescriptor
                            {
                                Subject = new ClaimsIdentity(new[] { new Claim("name", genericUser.DisplayName), new Claim("emails", genericUser.UserId) }),
                                Expires = DateTime.UtcNow.AddHours(1),
                                Issuer = @"https://sts.windows.net/0370b2d9-ab15-412b-8536-489b933ee591",
                                Audience = "https://rgmsgtestsrv01.service.signalr.net/client/?hub=chatroom"
                                //Audience = "9e640356-6292-4674-90c0-926bf340d736"
                                //Issuer = _configuration["Jwt:Issuer"],
                                //Audience = _configuration["Jwt:Audience"],
                                //SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                            };
                            var token = tokenHandler.CreateToken(tokenDescriptor);
                            return tokenHandler.WriteToken(token);
                        };
                    });


                    return request;

                case ServiceTokenCredential serviceCredential:
                    request.Services.Configure<HttpConnectionOptions>(options =>
                    {
                        options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                        options.AccessTokenProvider = async () =>
                        {
                            var opts = new TokenRequestContext(serviceCredential.Scopes);
                            //var bearer = await serviceCredential.Credential.GetTokenAsync(opts, CancellationToken.None);



                            string[] scopes = new string[] { "user.read" };

                            var app = PublicClientApplicationBuilder.Create("35a21cb0-bf6e-4de8-a7ad-736afc400ae8")
                                .WithTenantId("0370b2d9-ab15-412b-8536-489b933ee591")
                                .WithRedirectUri("http://localhost:50270")
                                .Build();

                            var accounts = await app.GetAccountsAsync();

                            AuthenticationResult result;
                            try
                            {
                                result = await app.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                                  .ExecuteAsync();
                            }
                            catch (MsalUiRequiredException)
                            {
                                result = await app.AcquireTokenInteractive(scopes)
                                .ExecuteAsync();
                            }








                            return result.IdToken;
                            //return bearer.Token;
                        };
                    });

                    return request;

                case ClientSecretCredential clientSecret:
                    request.Services.Configure<HttpConnectionOptions>(options =>
                    {
                        options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                        options.AccessTokenProvider = async () =>
                        {
                            var confidentialClientApplication = ConfidentialClientApplicationBuilder
                            .Create(clientSecret.ClientId)
                            .WithTenantId(clientSecret.TenantId)
                            .WithClientSecret(clientSecret.Secret)
                            .Build();

                            // direct the client to use an in-memory token cache...
                            confidentialClientApplication.AddInMemoryTokenCache();
                            var url = clientSecret.Scope
                                ?? clientSecret.ClientId + "/.default";

                            var bearer = await confidentialClientApplication.AcquireTokenForClient(new[] { url.ToString() }).ExecuteAsync();

                            return bearer.AccessToken;
                        };
                    });

                    return request;

                default:
                    throw new Exception($"Unhandled credential type '{credential.GetType().Name}' encountered in authentication handler.");

            }
        }

        #endregion

    }

}
