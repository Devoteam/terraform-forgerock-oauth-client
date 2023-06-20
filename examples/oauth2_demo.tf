module "root_demo" {
  ##
  ## Module Source
  ## 
  ### Fetch module from remote git repo (use 'ref' to indicate branch/tag/commit )
  source = "github.com/Devoteam/terraform-forgerock-oauth-client.git?ref=v0.1.0"
  ### Or via terraform registry 
  ### TODO: 

  ## Provider Config
  providers = {
    restapi = restapi.api_v2
  }

  ## explicit dependencies
  depends_on = []

  ## OAUth client config
  am_oauth2_client_realm = "/"
  am_oauth2_client_id    = "foo"

  am_oauth2_client_scopes = ["openid", "profile", "email"]
  am_oauth2_client_redirectionUris = [
    "http://127.0.0.1:5556/auth/callback"
  ]
  am_oauth2_client_clientType              = "Public"
  am_oauth2_client_tokenEndpointAuthMethod = "none"
  am_oauth2_client_grantTypes              = ["authorization_code", "client_credentials", "refresh_token"]
  am_oauth2_client_descriptions            = ["Test client"]

}
