// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"code.gitea.io/gitea/modules/log"
)

// JWT settings for standalone JWT authentication
var JWT = struct {
	Enabled            bool
	HeaderName         string   // HTTP header name containing the JWT token
	JWKSURL            string   // URL to fetch public keys for validation
	Issuer             string   // Expected issuer claim in JWT
	Audience           []string // Expected audience claim(s) in JWT
	SkipIssuerCheck    bool     // Skip issuer validation (useful for multiple issuers)
	SkipAudienceCheck  bool     // Skip audience validation
	UsernameClaim      string   // JWT claim containing the username (e.g., "sub", "preferred_username", "email")
	RolesClaim         string   // JWT claim containing user roles (e.g., "roles", "groups")
}{
	Enabled:            false,
	HeaderName:         "Authorization", // Default to Authorization header
	JWKSURL:            "",
	Issuer:             "gitea",
	Audience:           []string{"gitea"},
	SkipIssuerCheck:    false,
	SkipAudienceCheck:  false,
	UsernameClaim:      "preferred_username",
	RolesClaim:         "roles",
}

func loadJWTFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("jwt")
	JWT.Enabled = sec.Key("ENABLED").MustBool(false)
	
	if !JWT.Enabled {
		return
	}

	// Header name containing the JWT token
	JWT.HeaderName = sec.Key("HEADER_NAME").MustString("Authorization")
	
	// JWKS URL for validation (required)
	JWT.JWKSURL = sec.Key("JWKS_URL").MustString("")
	if JWT.JWKSURL == "" {
		log.Fatal("[jwt] JWT is enabled but JWKS_URL is not configured. This is required for JWT validation.")
	}

	// Issuer and audience validation
	JWT.Issuer = sec.Key("ISSUER").MustString("gitea")
	JWT.Audience = sec.Key("AUDIENCE").Strings(",")
	if len(JWT.Audience) == 0 {
		JWT.Audience = []string{"gitea"}
	}

	JWT.SkipIssuerCheck = sec.Key("SKIP_ISSUER_CHECK").MustBool(false)
	JWT.SkipAudienceCheck = sec.Key("SKIP_AUDIENCE_CHECK").MustBool(false)
	
	// Claims mapping
	JWT.UsernameClaim = sec.Key("USERNAME_CLAIM").MustString("preferred_username")
	JWT.RolesClaim = sec.Key("ROLES_CLAIM").MustString("roles")
	
	log.Info("[jwt] JWT authentication enabled with JWKS URL: %s", JWT.JWKSURL)
	log.Info("[jwt] JWT header name: %s", JWT.HeaderName)
	log.Info("[jwt] Username claim: %s, Roles claim: %s", JWT.UsernameClaim, JWT.RolesClaim)
}
