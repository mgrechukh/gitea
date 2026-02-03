// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"encoding/json"

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
	JWKSCacheTTL       int64    // JWKS cache TTL in seconds (default: 3600)
	JWKSHTTPTimeout    int      // JWKS HTTP request timeout in seconds (default: 10)
	
	// Auto-provisioning settings
	AutoRegister      bool                // Enable automatic user creation
	DefaultOrgID      int64               // Organization ID for auto-created users
	RoleToTeamMapping map[string][]string // Map JWT roles to Gitea team names
	DefaultEmail      string              // Default email domain if not in JWT
	DefaultIsActive   bool                // Whether auto-created users are active
	DefaultIsAdmin    bool                // Whether auto-created users are admins
	EmailClaim        string              // JWT claim for email (default: "email")
	FullNameClaim     string              // JWT claim for full name (default: "name")
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
	JWKSCacheTTL:       3600,  // 1 hour default
	JWKSHTTPTimeout:    10,    // 10 seconds default
	
	// Auto-provisioning defaults
	AutoRegister:      false,
	DefaultOrgID:      0,
	RoleToTeamMapping: make(map[string][]string),
	DefaultEmail:      "@gitea.local",
	DefaultIsActive:   true,
	DefaultIsAdmin:    false,
	EmailClaim:        "email",
	FullNameClaim:     "name",
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
	
	// JWKS settings
	JWT.JWKSCacheTTL = sec.Key("JWKS_CACHE_TTL").MustInt64(3600)
	if JWT.JWKSCacheTTL <= 0 {
		log.Warn("[jwt] Invalid JWKS cache TTL, using default 3600 seconds")
		JWT.JWKSCacheTTL = 3600
	}
	
	JWT.JWKSHTTPTimeout = sec.Key("JWKS_HTTP_TIMEOUT").MustInt(10)
	if JWT.JWKSHTTPTimeout <= 0 {
		log.Warn("[jwt] Invalid JWKS HTTP timeout, using default 10 seconds")
		JWT.JWKSHTTPTimeout = 10
	}
	
	log.Info("[jwt] JWT authentication enabled with JWKS URL: %s", JWT.JWKSURL)
	log.Info("[jwt] JWT header name: %s", JWT.HeaderName)
	log.Info("[jwt] Username claim: %s, Roles claim: %s", JWT.UsernameClaim, JWT.RolesClaim)
	log.Info("[jwt] JWKS cache TTL: %d seconds, HTTP timeout: %d seconds", JWT.JWKSCacheTTL, JWT.JWKSHTTPTimeout)
	
	// Auto-provisioning settings
	JWT.AutoRegister = sec.Key("AUTO_REGISTER").MustBool(false)
	JWT.DefaultOrgID = sec.Key("DEFAULT_ORG_ID").MustInt64(0)
	JWT.DefaultIsActive = sec.Key("DEFAULT_IS_ACTIVE").MustBool(true)
	JWT.DefaultIsAdmin = sec.Key("DEFAULT_IS_ADMIN").MustBool(false)
	JWT.EmailClaim = sec.Key("EMAIL_CLAIM").MustString("email")
	JWT.FullNameClaim = sec.Key("FULL_NAME_CLAIM").MustString("name")
	JWT.DefaultEmail = sec.Key("DEFAULT_EMAIL").MustString("@gitea.local")
	
	// Parse role to team mapping (JSON format)
	mappingJSON := sec.Key("ROLE_TO_TEAM_MAPPING").MustString("{}")
	if err := json.Unmarshal([]byte(mappingJSON), &JWT.RoleToTeamMapping); err != nil {
		log.Warn("[jwt] Failed to parse ROLE_TO_TEAM_MAPPING: %v", err)
		JWT.RoleToTeamMapping = make(map[string][]string)
	}
	
	if JWT.AutoRegister {
		log.Info("[jwt] Auto-registration enabled")
		if JWT.DefaultOrgID > 0 {
			log.Info("[jwt] Default organization ID: %d", JWT.DefaultOrgID)
			log.Info("[jwt] Role to team mappings: %d configured", len(JWT.RoleToTeamMapping))
		}
	}
}
