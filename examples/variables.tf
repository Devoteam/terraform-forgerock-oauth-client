##
## Tenant settings
##


variable "am_base_url" {
  description = "The Base Url for the Forgerops API"
  type        = string
}

##
## Auth Variable
## 
variable "am_auth_username" {
  description = "Username of admamin  in the realm"
  type        = string
  default     = "amadmin"
}

variable "am_auth_password" {
  description = "password of admamin in the realm"
  type        = string
  sensitive   = true
}

