# Terraform Module: Forgerock OAuth Client

## Description 

Terraform module to manage Forgerock AM's Oauth Client via AM REST API. 

## Provider

This module relies on [Mastercard/restapi](https://registry.terraform.io/providers/Mastercard/restapi/latest) provider to interact with AM's REST API.

## Usage

### Public OAuth Client

```hcl

module "root_enduser_ui" {
  ##
  ## Module Source
  ## 
  ### Fetch module from remote git repo (use 'ref' to indicate branch/tag/commit )
  source = "github.com/Devoteam/terraform-forgerock-oauth-client.git?ref=v0.1.0"
  ### Or via terraform registry 
  ### TODO: 

  ## Provider Config
  providers = {
    restapi = restapi.api_v2 ## use restapi alias 'api_v2' (see configuration bellow)
  }

  ## explicit dependencies
  depends_on = []

  ## OAUth client config
  am_oauth2_client_realm = "/" ## Top level realm can be either "/" or "root"
  am_oauth2_client_id    = "end-user-ui"

  am_oauth2_client_scopes = ["openid", "fr:idm:*", "profile"]
  am_oauth2_client_redirectionUris = [
    "http://127.0.0.1:5556/auth/callback",
    "${var.am_base_url}/enduser/appAuthHelperRedirect.html",
    "${var.am_base_url}/enduser/sessionCheck.html",
    "http://localhost:8888/enduser/appAuthHelperRedirect.html",
    "http://localhost:8888/enduser/sessionCheck.html"

  ]
  am_oauth2_client_clientType              = "Public"
  am_oauth2_client_tokenEndpointAuthMethod = "none"
  am_oauth2_client_grantTypes              = ["authorization_code", "implicit"]
  am_oauth2_client_descriptions            = ["root End User UI Client"]
}

```

### Confidential OAuth Client 

The OAuth client secret can set via the module variable `am_oauth2_client_secret` (which should typically be set via a sensitive terraform variable in your project), and `am_oauth2_client_secret_override` module variable can be used to explicitly override the client_secret on the AM server.

Because `am_oauth2_client_secret` is flagged as **sensitive** variable in the module, terraform will hide the entire request body from the terraform plan and apply output. In order to keep the useful terraform diff on plan and apply, the `am_oauth2_client_secret` will ONLY be included in the request body (and thus causing the terraform output to be hidden) if the `am_oauth2_client_secret_override` is explicitly set to `true`. 

> NOTE: if `am_oauth2_client_secret_override` is set to `false` the "client_secret" in the request is set to `null` in which case AM keeps the last known client_secret in its configuration.


```hcl

module "alpha_oidc_client_demo" {
  ##
  ## Module Source
  ## 
  ### Fetch module from remote git repo (use 'ref' to indicate branch/tag/commit )
  source = "github.com/Devoteam/terraform-forgerock-oauth-client.git?ref=v0.1.0"
  ### Or via terraform registry 
  ### TODO: 

  ## Provider Config
  providers = {
    restapi = restapi.api_v2 ## use restapi alias 'api_v2' (see configuration bellow)
  }

  ## explicit dependencies
  depends_on = []

  ## OAUth client config
  am_oauth2_client_realm = "alpha" ## Sub realm should NOT include leading "/"
  am_oauth2_client_id    = "oidc-client-demo"

  am_oauth2_client_scopes = ["openid","profile", "email"]
  am_oauth2_client_redirectionUris = [
    "http://127.0.0.1:5556/auth/callback"
  ]

  ## Set client type and auth method
  am_oauth2_client_clientType              = "Confidential"
  am_oauth2_client_tokenEndpointAuthMethod = "client_secret_post"

  ## Handling client secret
  ### create the following variables in your terraform project:
  ### 
  ### variable "oauth_confidential_client_secret" {
  ###   description = "client secret for 'oidc-client-demo'"
  ###   type        = string
  ###   sensitive   = true
  ###   default     = null ## forgerock API keep last stored client_secret
  ### }
  ### variable "oauth_confidential_client_secret_override" {
  ###   description = "overrude client secret for 'oidc-client-demo'"
  ###   type        = bool
  ###   default     = false
  ### }
  ###
  ### Then set the folloring env variable
  ###
  ###   export TF_VAR_oauth_confidential_client_secret_override=true
  ###   export TF_VAR_oauth_confidential_client_secret="your-client-secret"
  ###
  ### The client secret will only be overritten when 'TF_VAR_oauth_confidential_client_secret_override=true' is set
  ### 
  am_oauth2_client_secret          = var.oauth_confidential_client_secret
  am_oauth2_client_secret_override = var.oauth_confidential_client_secret_override
}

```



### Providers Config

* Providers version 
```hcl
terraform {
  required_providers {
    restapi = {
      source  = "Mastercard/restapi"
      version = "1.17.0"
    }

    http = {
      source  = "hashicorp/http"
      version = "3.2.0"
    }
  }
}
  
```

* Authentication to AM server

```hcl
## https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
provider "http" {
  alias = "http"
}

## https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
data "http" "sso_token" {
  // Authenticate in root realm
  ### update the tree name in the url according to your configuration
  url    = "${var.am_base_url}/am/json/realms/root/authenticate"
  method = "POST"

  ## skip self-sign cert validation
  // insecure = true

  request_headers = {
    Accept-API-Version = "resource=2.0, protocol=1.0"
    X-OpenAM-Username  = "${var.am_auth_username}"
    X-OpenAM-Password  = "${var.am_auth_password}"
  }
}


## https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
data "http" "server_info" {
  // Authenticate in root realm
  url    = "${var.am_base_url}/am/json/serverinfo/*"
  method = "GET"

  ## skip self-sign cert validation
  insecure = true

}

```
* Restapi provider configuration 

```hcl
# https://registry.terraform.io/providers/Mastercard/restapi/latest/docs
provider "restapi" {
  ## This provider can be uses for oauth2 client resources
  alias = "api_v2"
  # Configuration options

  ## base uri
  uri = var.am_base_url
  ## If using self-signed certs
  // insecure             = true
  write_returns_object = true


  ## conditional headers: 
  headers = {
    ## Read Forgeock API documentation for more info about
    ## mandatory Headers 
    Accept-API-Version = "protocol=2.0,resource=1.0"
    X-Requested-With   = "XMLHttpRequest"
    ## get the IplanetDirectoryPro cookie name and sso token value from data provider
    Cookie             = "${jsondecode(data.http.server_info.response_body).cookieName}=${jsondecode(data.http.sso_token.response_body).tokenId}"
  }

}

```

## Examples

See [./examples](./examples) directory for complete example.


## Compatibility

| terraform module | AM version |
| ---------------- | ---------- |
| v0.1.0 | 7.2.X |


## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

See [LICENSE](./LICENSE) for full details.

