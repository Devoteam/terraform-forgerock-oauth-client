##
## Mandatory
##
variable "am_oauth2_client_realm" {
  description = "Realm where to configure the OIDC client"
  type        = string
}

variable "am_oauth2_client_id" {
  description = "The client id"
  type        = string
}


### Secret
variable "am_oauth2_client_secret" {
  description = "The client secret"
  type        = string
  sensitive   = true
  default     = null
}

variable "am_oauth2_client_secret_override" {
  description = "The client secret"
  type        = bool
  default     = false
}

variable "am_oauth2_client_tokenEndpointAuthMethod" {
  description = "The client authentication method"
  type        = string
  default     = "client_secret_basic"

  validation {
    condition     = contains(["client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth", "none"], var.am_oauth2_client_tokenEndpointAuthMethod)
    error_message = "Valid values are (client_secret_basic, client_secret_post, private_key_jwt, tls_client_auth, self_signed_tls_client_auth, none)."
  }
}


### Common 
variable "am_oauth2_client_scopes" {
  description = "The client scopes"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_defaultScopes" {
  description = "The client defaultScopes"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_redirectionUris" {
  description = "The client redirect uris"
  type        = list(string)
  default     = []
}


variable "am_oauth2_client_status" {
  description = "The client status"
  type        = string

  default = "Active"

  validation {
    condition     = contains(["Active", "Inactive"], var.am_oauth2_client_status)
    error_message = "Valid values are (Active, Inactive)."
  }

}

variable "am_oauth2_client_clientType" {
  description = "The client Type"
  type        = string

  default = "Confidential"

  validation {
    condition     = contains(["Confidential", "Public"], var.am_oauth2_client_clientType)
    error_message = "Valid values are (Confidential, Public)."
  }

}

### Fonctional settings
variable "am_oauth2_client_grantTypes" {
  description = "The client grantTypes"
  type        = list(string)
  default = [
    "authorization_code",
    "client_credentials"
  ]

  validation {
    condition = alltrue([
      for e in var.am_oauth2_client_grantTypes : contains([
        "implicit",
        "urn:ietf:params:oauth:grant-type:saml2-bearer",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "authorization_code",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:uma-ticket",
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ], e)
    ])
    error_message = "Invalid Grant Type"
  }
}

variable "am_oauth2_client_responseTypes" {
  description = "The client responseTypes"
  type        = list(string)
  default     = ["code", "token", "id_token"]

  validation {
    condition = alltrue([
      for e in var.am_oauth2_client_responseTypes : contains([
        "code",
        "token",
        "id_token",
        "code token",
        "token id_token",
        "code id_token",
        "code token id_token",
        "device_code",
        "device_code id_token"
      ], e)
    ])
    error_message = "Invalid Grant Type (code, token id_token, code token, token id_token, code id_token, code token id_token, device_code, device_code id_token) "
  }
}


variable "am_oauth2_client_subjectType" {
  description = "The client subjectType"
  type        = string

  default = "public"

  validation {
    condition     = contains(["public", "pairwise"], var.am_oauth2_client_subjectType)
    error_message = "Valid values are (public, pairwise)."
  }

}

variable "am_oauth2_client_sectorIdentifierUri" {
  description = "The client sectorIdentifierUri"
  type        = string

  default = null

}

variable "am_oauth2_client_tokenExchangeAuthLevel" {
  description = "The client tokenExchangeAuthLevel"
  type        = number

  default = 0
}

variable "am_oauth2_client_mixUpMitigation" {
  description = "The client mixUpMitigation"
  type        = bool

  default = false
}

variable "am_oauth2_client_require_pushed_authorization_requests" {
  description = "The client require_pushed_authorization_requests"
  type        = bool

  default = false
}



### Local Dev
variable "am_oauth2_client_loopbackInterfaceRedirection" {
  description = "The client loopbackInterfaceRedirection"
  type        = bool
  default     = false
}

### Consent Settings
variable "am_oauth2_client_isConsentImplied" {
  description = "The client isConsentImplied"
  type        = bool
  default     = true


}


### SPA Setting
variable "am_oauth2_client_javascriptOrigins" {
  description = "The client javascriptOrigins"
  type        = list(string)
  default     = []


}


### Client Display setting
variable "am_oauth2_client_descriptions" {
  description = "The client descriptions"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_name" {
  description = "The client name"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_displayName" {
  description = "The client displayName"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_logoUri" {
  description = "The client logoUri (format URI|locale)"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_clientUri" {
  description = "The client clientUri (format URI|locale)"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_policyUri" {
  description = "The client Privacy policyUri (format URI|locale)"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_tosURI" {
  description = "The client Privacy Terms of Service URI (format URI|locale)"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_contacts" {
  description = "The client email contact"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_softwareVersion" {
  description = "The client softwareVersion"
  type        = string
  default     = ""
}

variable "am_oauth2_client_softwareIdentity" {
  description = "The client softwareIdentity"
  type        = string
  default     = ""
}



### Timing 
variable "am_oauth2_client_refreshTokenLifetime" {
  description = "The client refreshTokenLifetime"
  type        = number
  default     = 0
}


variable "am_oauth2_client_accessTokenLifetime" {
  description = "The client accessTokenLifetime"
  type        = number
  default     = 0
}


variable "am_oauth2_client_authorizationCodeLifetime" {
  description = "The client authorizationCodeLifetime"
  type        = number
  default     = 0
}

variable "am_oauth2_client_refreshTokenGracePeriod" {
  description = "The client refreshTokenGracePeriod"
  type        = number
  default     = 0
}

## OIDC
variable "am_oauth2_client_jwtTokenLifetime" {
  description = "The client OIDC jwtTokenLifetime"
  type        = number
  default     = 0
}

variable "am_oauth2_client_defaultMaxAge" {
  description = "The client OIDC defaultMaxAge"
  type        = number
  default     = 600
}

variable "am_oauth2_client_defaultMaxAgeEnabled" {
  description = "The client OIDC defaultMaxAgeEnabled"
  type        = bool
  default     = false
}



### Custom 
variable "am_oauth2_client_customProperties" {
  description = "The client customProperties"
  type        = list(string)
  default     = []
}


### Dynamic Registration
variable "am_oauth2_client_registration_requestUris" {
  description = "The client registration requestUris"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_registration_updateAccessToken" {
  description = "The client registration updateAccessToken"
  type        = string
  default     = ""
}

### Value Templace
variable "am_oauth2_client_agentgroup" {
  description = "The client agentgroup"
  type        = string

  default = ""
}


##
## Response Format
##
variable "am_oauth2_client_userinfoResponseFormat" {
  description = "The client userinfoResponseFormat"
  type        = string

  default = "JSON"
  validation {
    condition     = contains(["JSON", "ENCRYPTED_JWT", "SIGNED_THEN_ENCRYPTED_JWT", "SIGNED_JWT"], var.am_oauth2_client_userinfoResponseFormat)
    error_message = "Invalid userinfoResponseFormat."
  }

}
variable "am_oauth2_client_tokenIntrospectionResponseFormat" {
  description = "The client tokenIntrospectionResponseFormat"
  type        = string

  default = "JSON"
  validation {
    condition     = contains(["JSON", "ENCRYPTED_JWT", "SIGNED_THEN_ENCRYPTED_JWT", "SIGNED_JWT"], var.am_oauth2_client_tokenIntrospectionResponseFormat)
    error_message = "Invalid userinfoResponseFormat."
  }

}


##
## OIDC Settings
##
variable "am_oauth2_client_claims" {
  description = "The client OIDC claims"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_defaultAcrValues" {
  description = "The client OIDC defaultAcrValues"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_postLogoutRedirectUri" {
  description = "The client OIDC postLogoutRedirectUri"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_clientSessionUri" {
  description = "The client OIDC clientSessionUri"
  type        = string
  default     = null
}

variable "am_oauth2_client_backchannel_logout_uri" {
  description = "The client OIDC backchannel_logout_uri"
  type        = string
  default     = null
}

variable "am_oauth2_client_backchannel_logout_session_required" {
  description = "The client OIDC backchannel_logout_session_required"
  type        = bool
  default     = false
}





##
## Security Setting
##
variable "am_oauth2_client_tokenEndpointAuthSigningAlgorithm" {
  description = "The client tokenEndpointAuthSigningAlgorithm"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_userinfoSignedResponseAlg" {
  description = "The client userinfoSignedResponseAlg"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_userinfoEncryptedResponseAlg" {
  description = "The client userinfoEncryptedResponseAlg"
  type        = string

  default = null
}

variable "am_oauth2_client_userinfoEncryptedResponseEncryptionAlgorithm" {
  description = "The client userinfoEncryptedResponseEncryptionAlgorithm"
  type        = string

  default = "A128CBC-HS256"

}

variable "am_oauth2_client_idTokenSignedResponseAlg" {
  description = "The client idTokenSignedResponseAlg"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_authorizationResponseSigningAlgorithm" {
  description = "The client authorizationResponseSigningAlgorithm"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_tokenIntrospectionSignedResponseAlg" {
  description = "The client tokenIntrospectionSignedResponseAlg"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_requestParameterSignedAlg" {
  description = "The client requestParameterSignedAlg"
  type        = string

  default = "RS256"

}

variable "am_oauth2_client_requestParameterEncryptedEncryptionAlgorithm" {
  description = "The client requestParameterEncryptedEncryptionAlgorithm"
  type        = string

  default = "A128CBC-HS256"
}

variable "am_oauth2_client_requestParameterEncryptedAlg" {
  description = "The client requestParameterEncryptedAlg"
  type        = string

  default = null
}


variable "am_oauth2_client_tokenIntrospectionEncryptedResponseEncryptionAlgorithm" {
  description = "The client tokenIntrospectionEncryptedResponseEncryptionAlgorithm"
  type        = string

  default = "A128CBC-HS256"

}

variable "am_oauth2_client_tokenIntrospectionEncryptedResponseAlg" {
  description = "The client tokenIntrospectionEncryptedResponseAlg"
  type        = string

  default = "RSA-OAEP-256"

}

variable "am_oauth2_client_idTokenEncryptionEnabled" {
  description = "idTokenEncryptionEnabled"
  type        = bool
  default     = false
}

variable "am_oauth2_client_idTokenEncryptionAlgorithm" {
  description = "idTokenEncryptionEnabled"
  type        = string
  default     = "RSA-OAEP-256"
}

variable "am_oauth2_client_idTokenEncryptionMethod" {
  description = "idTokenEncryptionMethod"
  type        = string
  default     = "A128CBC-HS256"
}

variable "am_oauth2_client_idTokenPublicEncryptionKey" {
  description = "The client idTokenPublicEncryptionKey"
  type        = string

  default = null
}


variable "am_oauth2_client_authorizationResponseEncryptionMethod" {
  description = "The client authorizationResponseEncryptionMethod"
  type        = string

  default = null
}

variable "am_oauth2_client_authorizationResponseEncryptionAlgorithm" {
  description = "The client authorizationResponseEncryptionAlgorithm"
  type        = string

  default = null
}


variable "am_oauth2_client_mTLSCertificateBoundAccessTokens" {
  description = "The client mTLSCertificateBoundAccessTokens"
  type        = bool

  default = false
}

variable "am_oauth2_client_mTLSSubjectDN" {
  description = "The client mTLSSubjectDN"
  type        = string

  default = null
}

variable "am_oauth2_client_mTLSTrustedCert" {
  description = "The client mTLSTrustedCert"
  type        = string

  default = null
}


variable "am_oauth2_client_clientJwtPublicKey" {
  description = "The client clientJwtPublicKey"
  type        = string

  default = null
}

variable "am_oauth2_client_publicKeyLocation" {
  description = "The client publicKeyLocation"
  type        = string

  default = "jwks_uri"

  validation {
    condition     = contains(["jwks_uri", "jwks", "x509"], var.am_oauth2_client_publicKeyLocation)
    error_message = "Valid value (jwks_uri, jwks, x509)."
  }

}

variable "am_oauth2_client_jwksUri" {
  description = "The client jwksUri"
  type        = string

  default = null
}

variable "am_oauth2_client_jwkSet" {
  description = "The client jwkSet"
  type        = string

  default = null
}

variable "am_oauth2_client_jwkStoreCacheMissCacheTime" {
  description = "The client jwkStoreCacheMissCacheTime"
  type        = number

  default = 60000
}

variable "am_oauth2_client_jwksCacheTimeout" {
  description = "The client jwksCacheTimeout"
  type        = number

  default = 3600000
}

### UMA
variable "am_oauth2_client_uma_claimsRedirectionUris" {
  description = "The client uma claimsRedirectionUris"
  type        = list(string)
  default     = []
}

##
## Override
##
variable "am_oauth2_client_providerOverridesEnabled" {
  description = "override OIDC Claims Script ID"
  type        = bool
  default     = false
}

variable "am_oauth2_client_override_oidcClaimsScript_id" {
  description = "override oidcClaimsScript_id"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_accessTokenModificationScript_id" {
  description = "override accessTokenModificationScript_id"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_remoteConsentServiceId" {
  description = "Client Override remoteConsentServiceId"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_oidcMayActScript" {
  description = "Client Override oidcMayActScript"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_accessTokenMayActScript" {
  description = "Client Override oidcMayActScript"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_authorizeEndpointDataProviderScript" {
  description = "Client Override authorizeEndpointDataProviderScript"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_validateScopeScript" {
  description = "Client Override validateScopeScript"
  type        = string
  default     = "[EMPTY]"
}

variable "am_oauth2_client_override_evaluateScopeScript" {
  description = "Client Override evaluateScopeScript"
  type        = string
  default     = "[EMPTY]"
}


variable "am_oauth2_client_override_issueRefreshToken" {
  description = "Client Override issueRefreshToken"
  type        = bool
  default     = true
}

variable "am_oauth2_client_override_clientsCanSkipConsent" {
  description = "Client Override clientsCanSkipConsent"
  type        = bool
  default     = true
}

variable "am_oauth2_client_override_issueRefreshTokenOnRefreshedToken" {
  description = "Client Override issueRefreshTokenOnRefreshedToken"
  type        = bool
  default     = true
}

variable "am_oauth2_client_override_statelessTokensEnabled" {
  description = "Client Override statelessTokensEnabled"
  type        = bool
  default     = true
}



variable "am_oauth2_client_override_tokenEncryptionEnabled" {
  description = "Client Override tokenEncryptionEnabled"
  type        = bool
  default     = false
}

variable "am_oauth2_client_override_enableRemoteConsent" {
  description = "Client Override enableRemoteConsent"
  type        = bool
  default     = false
}

variable "am_oauth2_client_override_usePolicyEngineForScope" {
  description = "Client Override usePolicyEngineForScope"
  type        = bool
  default     = false
}

variable "am_oauth2_client_override_scopesPolicySet" {
  description = "Client Override scopesPolicySet"
  type        = string
  default     = ""
}

variable "am_oauth2_client_override_overrideableOIDCClaims" {
  description = "Client Override overrideableOIDCClaims"
  type        = list(string)
  default     = []
}

variable "am_oauth2_client_override_evaluateScopeClass" {
  description = "Client Override evaluateScopeClass"
  type        = string
  default     = "org.forgerock.oauth2.core.plugins.registry.DefaultScopeEvaluator"
}

variable "am_oauth2_client_override_validateScopeClass" {
  description = "Client Override validateScopeClass"
  type        = string
  default     = "org.forgerock.oauth2.core.plugins.registry.DefaultScopeValidator"
}

variable "am_oauth2_client_override_authorizeEndpointDataProviderClass" {
  description = "Client Override authorizeEndpointDataProviderClass"
  type        = string
  default     = "org.forgerock.oauth2.core.plugins.registry.DefaultEndpointDataProvider"
}

variable "am_oauth2_client_override_accessTokenModificationPluginType" {
  description = "Client Override accessTokenModificationPluginType"
  type        = string
  default     = "PROVIDER"

  validation {
    condition     = contains(["PROVIDER", "JAVA", "SCRIPTED"], var.am_oauth2_client_override_accessTokenModificationPluginType)
    error_message = "Valid values are (PROVIDER, JAVA, SCRIPTED)."
  }
}

variable "am_oauth2_client_override_validateScopePluginType" {
  description = "Client Override validateScopePluginType"
  type        = string
  default     = "PROVIDER"

  validation {
    condition     = contains(["PROVIDER", "JAVA", "SCRIPTED"], var.am_oauth2_client_override_validateScopePluginType)
    error_message = "Valid values are (PROVIDER, JAVA, SCRIPTED)."
  }
}

variable "am_oauth2_client_override_oidcClaimsPluginType" {
  description = "Client Override oidcClaimsPluginType"
  type        = string
  default     = "PROVIDER"

  validation {
    condition     = contains(["PROVIDER", "JAVA", "SCRIPTED"], var.am_oauth2_client_override_oidcClaimsPluginType)
    error_message = "Valid values are (PROVIDER, JAVA, SCRIPTED)."
  }
}

variable "am_oauth2_client_override_authorizeEndpointDataProviderPluginType" {
  description = "Client Override authorizeEndpointDataProviderPluginType"
  type        = string
  default     = "PROVIDER"

  validation {
    condition     = contains(["PROVIDER", "JAVA", "SCRIPTED"], var.am_oauth2_client_override_authorizeEndpointDataProviderPluginType)
    error_message = "Valid values are (PROVIDER, JAVA, SCRIPTED)."
  }

}

variable "am_oauth2_client_override_evaluateScopePluginType" {
  description = "Client Override evaluateScopePluginType"
  type        = string
  default     = "PROVIDER"

  validation {
    condition     = contains(["PROVIDER", "JAVA", "SCRIPTED"], var.am_oauth2_client_override_evaluateScopePluginType)
    error_message = "Valid values are (PROVIDER, JAVA, SCRIPTED)."
  }
}

