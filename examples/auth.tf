
## https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
data "http" "sso_token" {
  // Authenticate in root realm
  url    = "${var.am_base_url}/am/json/realms/root/authenticate"
  method = "POST"

  ## skip self-sign cert validation
  insecure = true

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

