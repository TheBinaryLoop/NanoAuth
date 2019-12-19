using IdentityServer4.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NanoAuth
{
    public class IdentityServerResourceManager
    {
        private readonly string _identityResourceConfigPath;
        private readonly string _apiResourceConfigPath;
        private readonly string _clientConfigPath;

        public IdentityServerResourceManager(string rootConfigPath)
            : this(Path.Combine(rootConfigPath, "IdentityResources"),
                Path.Combine(rootConfigPath, "ApiResources"), Path.Combine(rootConfigPath, "Clients"))
        {
        }

        public IdentityServerResourceManager(string identityResourceConfigPath,
            string apiResourceConfigPath, string clientConfigPath)
        {
            if (!Directory.Exists(identityResourceConfigPath))
                throw new DirectoryNotFoundException(identityResourceConfigPath);
            _identityResourceConfigPath = identityResourceConfigPath;

            if (!Directory.Exists(apiResourceConfigPath))
                throw new DirectoryNotFoundException(apiResourceConfigPath);
            _apiResourceConfigPath = apiResourceConfigPath;

            if (!Directory.Exists(clientConfigPath))
                throw new DirectoryNotFoundException(clientConfigPath);
            _clientConfigPath = clientConfigPath;
        }

        public IEnumerable<IdentityResource> LoadIdentityResources()
        {
            var resources = new List<IdentityResource>();

            // Get all json files in directory
            var files = Directory.EnumerateFiles(_identityResourceConfigPath, "IR_*.json")
                .Select(x => Path.Combine(_identityResourceConfigPath, x)).ToArray();

            if (files.Length <= 0)
            {
                //TODO: Warn user that no IdentityResources will be configured
                return resources;
            }

            // Load the IdentityResources
            foreach (var file in files)
            {
                try
                {
                    resources.Add(JsonConvert.DeserializeObject<IdentityResource>(File.ReadAllText(file)));
                }
                catch (Exception e)
                {
                    // ignored
                }
            }

            return resources;

            //return new IdentityResource[]
            //{
            //    new IdentityResources.OpenId(),
            //    new IdentityResources.Profile { Required = true }
            //};
        }

        public IEnumerable<ApiResource> LoadApiResources()
        {
            var apiResources = new List<ApiResource>();


            // Get all json files in directory
            var files = Directory.EnumerateFiles(_apiResourceConfigPath, "AR_*.json")
                .Select(x => Path.Combine(_apiResourceConfigPath, x)).ToArray();

            if (files.Length <= 0)
            {
                //TODO: Warn user that no ApiResources will be configured
                return apiResources;
            }

            // Load the IdentityResources
            foreach (var file in files)
            {
                try
                {
                    apiResources.Add(JsonConvert.DeserializeObject<ApiResource>(File.ReadAllText(file)));
                }
                catch (Exception e)
                {
                    // ignored
                }
            }

            return apiResources;

            //var apiResource = new ApiResource(NanoDDNSManagementScopeName, "NanoDDNS Management");
            //apiResource.Scopes.First().Required = true;
            //return new[]
            //{
            //    apiResource
            //};
        }

        public IEnumerable<Client> LoadClients()
        {
            var clients = new List<Client>();


            // Get all json files in directory
            var files = Directory.EnumerateFiles(_clientConfigPath, "CL_*.json")
                .Select(x => Path.Combine(_clientConfigPath, x)).ToArray();

            if (files.Length <= 0)
            {
                //TODO: Warn user that no clients will be configured
                return clients;
            }

            foreach (var file in files)
            {
                try
                {
                    var newClient = JsonConvert.DeserializeObject<Client>(File.ReadAllText(file));
                    newClient.ClientSecrets = newClient.ClientSecrets.Select(x =>
                    {
                        x.Value = x.Value.Sha256();
                        return x;
                    }).ToList();
                    clients.Add(newClient);
                }
                catch (Exception e)
                {
                    //ignored
                }
            }

            //File.WriteAllText("client.json", JsonConvert.SerializeObject(new Client
            //{
            //    ClientSecrets =
            //    {
            //        new Secret("secret".Sha512())
            //    },
            //    AllowedGrantTypes = GrantTypes.Code,
            //    AllowedScopes =
            //    {
            //        IdentityServerConstants.StandardScopes.OpenId, 
            //        IdentityServerConstants.StandardScopes.Profile,
            //        NanoDDNSManagementScopeName
            //    }
            //}, Formatting.Indented));

            return clients;

            //return new[]
            //{
            //    new Client
            //    {
            //        ClientId = "WebFrontend",
            //        AllowedGrantTypes = GrantTypes.Code,
            //        ClientSecrets =
            //        {
            //            new Secret(clientConfig.Secret.Sha256())
            //            //new Secret(clientConfig.Secret.Sha512())
            //        },
            //        RedirectUris = clientConfig.RedirectUris,
            //        PostLogoutRedirectUris =
            //        {
            //            "https://localhost:5003/signout-callback-oidc"
            //        },
            //        RefreshTokenUsage = TokenUsage.OneTimeOnly,
            //        AllowedScopes =
            //        {
            //            IdentityServerConstants.StandardScopes.OpenId,
            //            IdentityServerConstants.StandardScopes.Profile,
            //            NanoDDNSManagementScopeName
            //        },
            //        AllowOfflineAccess = true,
            //        AccessTokenLifetime = clientConfig.AccessTokenLifetime,
            //        RefreshTokenExpiration = TokenExpiration.Sliding,
            //        RequireConsent = true
            //    }
            //};
        }
    }
}
