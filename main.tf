
## https://registry.terraform.io/providers/Mastercard/restapi/latest/docs/resources/object
resource "restapi_object" "fr-oauth2-client" {
  ## Terrform Metadata
  path           = "${var.am_oauth2_client_realm}" == "/" || "${var.am_oauth2_client_realm}" == "root" ? "/am/json/realms/root/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}" : "/am/json/realms/root/realms/${var.am_oauth2_client_realm}/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}"
  read_path      = "${var.am_oauth2_client_realm}" == "/" || "${var.am_oauth2_client_realm}" == "root" ? "/am/json/realms/root/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}" : "/am/json/realms/root/realms/${var.am_oauth2_client_realm}/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}"
  update_path    = "${var.am_oauth2_client_realm}" == "/" || "${var.am_oauth2_client_realm}" == "root" ? "/am/json/realms/root/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}" : "/am/json/realms/root/realms/${var.am_oauth2_client_realm}/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}"
  destroy_path   = "${var.am_oauth2_client_realm}" == "/" || "${var.am_oauth2_client_realm}" == "root" ? "/am/json/realms/root/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}" : "/am/json/realms/root/realms/${var.am_oauth2_client_realm}/realm-config/agents/OAuth2Client/${var.am_oauth2_client_id}"
  update_method  = "PUT"
  create_method  = "PUT"
  destroy_method = "DELETE"
  object_id      = var.am_oauth2_client_id
  debug          = true

  ## OAuth Client Configuration
  ## Using 'jsonencode' function
  data = jsonencode({

    "_id" = "${var.am_oauth2_client_id}"

    coreOAuth2ClientConfig = {
      status = {
        inherited = false
        value     = "${var.am_oauth2_client_status}"
      }

      userpassword = var.am_oauth2_client_secret_override ? "${var.am_oauth2_client_secret}" : null

      clientType = {
        inherited = false
        value     = "${var.am_oauth2_client_clientType}"
      }

      scopes = {
        inherited = false
        value     = var.am_oauth2_client_scopes
      }

      redirectionUris = {
        inherited = false
        value     = var.am_oauth2_client_redirectionUris
      }

      loopbackInterfaceRedirection = {
        inherited = false
        value     = var.am_oauth2_client_loopbackInterfaceRedirection
      }


      defaultScopes = {
        inherited = false
        value     = var.am_oauth2_client_defaultScopes
      }

      refreshTokenLifetime = {
        inherited = false
        value     = var.am_oauth2_client_refreshTokenLifetime
      }

      accessTokenLifetime = {
        inherited = false
        value     = var.am_oauth2_client_accessTokenLifetime
      }

      authorizationCodeLifetime = {
        inherited = false
        value     = var.am_oauth2_client_authorizationCodeLifetime
      }

      agentgroup = "${var.am_oauth2_client_agentgroup}"

      clientName = {
        inherited = false
        value     = var.am_oauth2_client_name
      }

    }



    advancedOAuth2ClientConfig = {

      tokenEndpointAuthMethod = {
        inherited = false
        value     = "${var.am_oauth2_client_tokenEndpointAuthMethod}"
      }

      descriptions = {
        inherited = false
        value     = var.am_oauth2_client_descriptions
      }

      grantTypes = {
        inherited = false
        value     = var.am_oauth2_client_grantTypes
      }

      responseTypes = {
        inherited = false
        value     = var.am_oauth2_client_responseTypes
      }

      subjectType = {
        inherited = false
        value     = "${var.am_oauth2_client_subjectType}"
      }

      javascriptOrigins = {
        inherited = false
        value     = var.am_oauth2_client_javascriptOrigins
      }

      isConsentImplied = {
        inherited = false
        value     = var.am_oauth2_client_isConsentImplied
      }

      requestUris = {
        inherited = false
        value     = var.am_oauth2_client_registration_requestUris
      }

      logoUri = {
        inherited = false
        value     = var.am_oauth2_client_logoUri
      }

      clientUri = {
        inherited = false
        value     = var.am_oauth2_client_clientUri
      }

      policyUri = {
        inherited = false
        value     = var.am_oauth2_client_policyUri
      }

      tosURI = {
        inherited = false
        value     = var.am_oauth2_client_tosURI
      }

      contacts = {
        inherited = false
        value     = var.am_oauth2_client_contacts
      }

      tokenExchangeAuthLevel = {
        inherited = false
        value     = var.am_oauth2_client_tokenExchangeAuthLevel
      }

      name = {
        inherited = false
        value     = var.am_oauth2_client_displayName
      }

      updateAccessToken = {
        inherited = false
        value     = var.am_oauth2_client_registration_updateAccessToken
      }

      mixUpMitigation = {
        inherited = false
        value     = var.am_oauth2_client_mixUpMitigation
      }

      customProperties = {
        inherited = false
        value     = var.am_oauth2_client_customProperties

      }

      softwareVersion = {
        inherited = false
        value     = var.am_oauth2_client_softwareVersion
      }

      softwareIdentity = {
        inherited = false
        value     = var.am_oauth2_client_softwareIdentity
      }

      sectorIdentifierUri = {
        inherited = false
        value     = var.am_oauth2_client_sectorIdentifierUri
      }

      refreshTokenGracePeriod = {
        inherited = false
        value     = var.am_oauth2_client_refreshTokenGracePeriod
      }

      require_pushed_authorization_requests = {
        inherited = false
        value     = var.am_oauth2_client_require_pushed_authorization_requests
      }

    }

    signEncOAuth2ClientConfig = {

      tokenEndpointAuthSigningAlgorithm = {
        inherited = false
        value     = var.am_oauth2_client_tokenEndpointAuthSigningAlgorithm
      }

      userinfoSignedResponseAlg = {
        inherited = false
        value     = var.am_oauth2_client_userinfoSignedResponseAlg
      }

      userinfoEncryptedResponseAlg = {
        inherited = false
        value     = var.am_oauth2_client_userinfoEncryptedResponseAlg
      }

      userinfoEncryptedResponseEncryptionAlgorithm = {
        inherited = false
        value     = "${var.am_oauth2_client_userinfoEncryptedResponseEncryptionAlgorithm}"
      }



      idTokenSignedResponseAlg = {
        inherited = false
        value     = var.am_oauth2_client_idTokenSignedResponseAlg
      }

      ## - JSON
      ## - SIGNED_JWT
      userinfoResponseFormat = {
        inherited = false
        value     = "${var.am_oauth2_client_userinfoResponseFormat}"
      }

      tokenIntrospectionResponseFormat = {
        inherited = false
        value     = "${var.am_oauth2_client_tokenIntrospectionResponseFormat}"
      }

      idTokenEncryptionEnabled = {
        inherited = false
        value     = var.am_oauth2_client_idTokenEncryptionEnabled
      }

      tokenIntrospectionEncryptedResponseEncryptionAlgorithm = {
        inherited = false
        value     = "${var.am_oauth2_client_tokenIntrospectionEncryptedResponseEncryptionAlgorithm}"
      }

      requestParameterSignedAlg = {
        inherited = false
        value     = var.am_oauth2_client_requestParameterSignedAlg
      }

      requestParameterEncryptedEncryptionAlgorithm = {
        inherited = false
        value     = "${var.am_oauth2_client_requestParameterEncryptedEncryptionAlgorithm}"
      }

      requestParameterEncryptedAlg = {
        inherited = false
        value     = var.am_oauth2_client_requestParameterEncryptedAlg
      }



      idTokenPublicEncryptionKey = {
        inherited = false
        value     = var.am_oauth2_client_idTokenPublicEncryptionKey
      }

      idTokenEncryptionAlgorithm = {
        inherited = false
        value     = "${var.am_oauth2_client_idTokenEncryptionAlgorithm}"
      }

      idTokenEncryptionMethod = {
        inherited = false
        value     = "${var.am_oauth2_client_idTokenEncryptionMethod}"
      }

      authorizationResponseSigningAlgorithm = {
        inherited = false
        value     = "${var.am_oauth2_client_authorizationResponseSigningAlgorithm}"
      }

      authorizationResponseEncryptionMethod = {
        inherited = false
        value     = var.am_oauth2_client_authorizationResponseEncryptionMethod
      }

      authorizationResponseEncryptionAlgorithm = {
        inherited = false
        value     = var.am_oauth2_client_authorizationResponseEncryptionAlgorithm
      }


      mTLSCertificateBoundAccessTokens = {
        inherited = false
        value     = var.am_oauth2_client_mTLSCertificateBoundAccessTokens
      }

      mTLSSubjectDN = {
        inherited = false
        value     = var.am_oauth2_client_mTLSSubjectDN
      }

      mTLSTrustedCert = {
        inherited = false
        value     = var.am_oauth2_client_mTLSTrustedCert
      }

      publicKeyLocation = {
        inherited = false
        value     = "${var.am_oauth2_client_publicKeyLocation}"
      }

      clientJwtPublicKey = {
        inherited = false
        value     = var.am_oauth2_client_clientJwtPublicKey
      }

      jwksUri = {
        inherited = false
        value     = var.am_oauth2_client_jwksUri
      }


      jwkStoreCacheMissCacheTime = {
        inherited = false
        value     = var.am_oauth2_client_jwkStoreCacheMissCacheTime
      }

      jwksCacheTimeout = {
        inherited = false
        value     = var.am_oauth2_client_jwksCacheTimeout
      }

      jwkSet = {
        inherited = false
        value     = var.am_oauth2_client_jwkSet
      }


      tokenIntrospectionSignedResponseAlg = {
        inherited = false
        value     = "${var.am_oauth2_client_tokenIntrospectionSignedResponseAlg}"
      }


      tokenIntrospectionEncryptedResponseAlg = {
        inherited = false
        value     = "${var.am_oauth2_client_tokenIntrospectionEncryptedResponseAlg}"
      }
    }

    coreOpenIDClientConfig = {
      claims = {
        inherited = false
        value     = var.am_oauth2_client_claims
      }

      clientSessionUri = {
        inherited = false
        value     = var.am_oauth2_client_clientSessionUri
      }

      backchannel_logout_uri = {
        inherited = false
        value     = var.am_oauth2_client_backchannel_logout_uri
      }

      defaultAcrValues = {
        inherited = false
        value     = var.am_oauth2_client_defaultAcrValues
      }

      jwtTokenLifetime = {
        inherited = false
        value     = var.am_oauth2_client_jwtTokenLifetime
      }

      defaultMaxAgeEnabled = {
        inherited = false
        value     = var.am_oauth2_client_defaultMaxAgeEnabled
      }

      defaultMaxAge = {
        inherited = false
        value     = var.am_oauth2_client_defaultMaxAge
      }

      postLogoutRedirectUri = {
        inherited = false
        value     = var.am_oauth2_client_postLogoutRedirectUri
      }

      backchannel_logout_session_required = {
        inherited = false
        value     = var.am_oauth2_client_backchannel_logout_session_required
      }
    }

    overrideOAuth2ClientConfig = {
      providerOverridesEnabled          = var.am_oauth2_client_providerOverridesEnabled
      issueRefreshToken                 = var.am_oauth2_client_override_issueRefreshToken
      remoteConsentServiceId            = "${var.am_oauth2_client_override_remoteConsentServiceId}"
      tokenEncryptionEnabled            = var.am_oauth2_client_override_tokenEncryptionEnabled
      enableRemoteConsent               = var.am_oauth2_client_override_enableRemoteConsent
      usePolicyEngineForScope           = var.am_oauth2_client_override_usePolicyEngineForScope
      scopesPolicySet                   = var.am_oauth2_client_override_scopesPolicySet
      overrideableOIDCClaims            = var.am_oauth2_client_override_overrideableOIDCClaims
      oidcMayActScript                  = "${var.am_oauth2_client_override_oidcMayActScript}"
      oidcClaimsScript                  = "${var.am_oauth2_client_override_oidcClaimsScript_id}"
      accessTokenMayActScript           = "${var.am_oauth2_client_override_accessTokenMayActScript}"
      clientsCanSkipConsent             = var.am_oauth2_client_override_clientsCanSkipConsent
      accessTokenModificationScript     = "${var.am_oauth2_client_override_accessTokenModificationScript_id}"
      issueRefreshTokenOnRefreshedToken = var.am_oauth2_client_override_issueRefreshTokenOnRefreshedToken
      statelessTokensEnabled            = var.am_oauth2_client_override_statelessTokensEnabled

      evaluateScopeClass                      = "${var.am_oauth2_client_override_evaluateScopeClass}"
      accessTokenModificationPluginType       = "${var.am_oauth2_client_override_accessTokenModificationPluginType}"
      evaluateScopePluginType                 = "${var.am_oauth2_client_override_evaluateScopePluginType}"
      authorizeEndpointDataProviderScript     = "${var.am_oauth2_client_override_authorizeEndpointDataProviderScript}"
      validateScopeClass                      = "${var.am_oauth2_client_override_validateScopeClass}"
      authorizeEndpointDataProviderClass      = "${var.am_oauth2_client_override_authorizeEndpointDataProviderClass}"
      validateScopePluginType                 = "${var.am_oauth2_client_override_validateScopePluginType}"
      oidcClaimsPluginType                    = "${var.am_oauth2_client_override_oidcClaimsPluginType}"
      validateScopeScript                     = "${var.am_oauth2_client_override_validateScopeScript}"
      authorizeEndpointDataProviderPluginType = "${var.am_oauth2_client_override_authorizeEndpointDataProviderPluginType}"
      evaluateScopeScript                     = "${var.am_oauth2_client_override_evaluateScopeScript}"
    }

    coreUmaClientConfig = {
      claimsRedirectionUris = {
        inherited = false
        value     = var.am_oauth2_client_uma_claimsRedirectionUris
      }
    }

    "_type" = {
      "_id"        = "OAuth2Client"
      "name"       = "OAuth2 Clients"
      "collection" = true
    }
  })
}