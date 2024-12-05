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

                case WebTokenCredential userTokenAcquisition:
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
                                Expires = DateTime.UtcNow.AddHours(1)
                            };
                            var token = tokenHandler.CreateToken(tokenDescriptor);
                            return tokenHandler.WriteToken(token);
                        };
                    });


                    return request;

                case UserTokenCredential userCredential:
                    request.Services.Configure<HttpConnectionOptions>(options =>
                    {
                        options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                        options.AccessTokenProvider = async () =>
                        {

                            var tokenRequestContext = new TokenRequestContext(userCredential.Scopes);
                            var token = await userCredential.Credential.GetTokenAsync(tokenRequestContext, CancellationToken.None);
                            return token.Token;
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
