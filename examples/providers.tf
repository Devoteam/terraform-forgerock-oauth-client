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


## https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
provider "http" {
  alias = "http"
}

# https://registry.terraform.io/providers/Mastercard/restapi/latest/docs
provider "restapi" {
  ## This provider can be uses for oauth2 client resources
  alias = "api_v2"
  # Configuration options

  ## base uri
  uri = var.am_base_url
  ## If using self-signed certs
  insecure             = true
  write_returns_object = true


  ## conditional headers: 
  headers = {
    Accept-API-Version = "protocol=2.0,resource=1.0"
    X-Requested-With   = "XMLHttpRequest"
    Cookie             = "${jsondecode(data.http.server_info.response_body).cookieName}=${jsondecode(data.http.sso_token.response_body).tokenId}"
  }

}
