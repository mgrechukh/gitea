// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/models/organization"
	user_model "code.gitea.io/gitea/models/user"
	jwtutil "code.gitea.io/gitea/modules/auth/jwt"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	org_service "code.gitea.io/gitea/services/org"

	"github.com/golang-jwt/jwt/v5"
)

// Ensure the struct implements the interface.
var (
	_ Method = &JWT{}
)

// JWT implements the Auth interface and authenticates requests
// using JSON Web Tokens (JWT) validated against a JWKS endpoint.
type JWT struct{}

// Name represents the name of auth method
func (j *JWT) Name() string {
	return "jwt"
}

var (
	jwksClient     *jwtutil.JWKSClient
	jwksClientOnce sync.Once
)

// getJWKSClient returns a singleton JWKS client
func getJWKSClient() *jwtutil.JWKSClient {
	if setting.JWT.JWKSURL == "" {
		return nil
	}

	jwksClientOnce.Do(func() {
		cacheTTL := time.Duration(setting.JWT.JWKSCacheTTL) * time.Second
		httpTimeout := time.Duration(setting.JWT.JWKSHTTPTimeout) * time.Second
		jwksClient = jwtutil.NewJWKSClient(setting.JWT.JWKSURL, cacheTTL, httpTimeout)
	})

	return jwksClient
}

// parseJWTToken extracts the JWT token from the configured header
func parseJWTToken(req *http.Request) (string, bool) {
	headerName := setting.JWT.HeaderName
	headerValue := req.Header.Get(headerName)

	if headerValue == "" {
		return "", false
	}

	// If the header is Authorization, strip the "Bearer " prefix
	if strings.EqualFold(headerName, "Authorization") {
		// Remove "Bearer " prefix if present
		if strings.HasPrefix(headerValue, "Bearer ") {
			return strings.TrimPrefix(headerValue, "Bearer "), true
		}
		if strings.HasPrefix(headerValue, "bearer ") {
			return strings.TrimPrefix(headerValue, "bearer "), true
		}
	}

	// For other headers, use the value as-is
	return headerValue, true
}

// extractClaimValue extracts a claim value from JWT claims (supports nested paths with dots)
func extractClaimValue(claims jwt.MapClaims, claimPath string) (interface{}, bool) {
	// Split by dots to support nested claims like "user.username"
	parts := strings.Split(claimPath, ".")

	var current interface{} = claims
	for _, part := range parts {
		switch v := current.(type) {
		case jwt.MapClaims:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// extractUsername extracts the username from JWT claims
func extractUsername(claims jwt.MapClaims) (string, error) {
	// Try the configured username claim
	if val, ok := extractClaimValue(claims, setting.JWT.UsernameClaim); ok {
		if username, ok := val.(string); ok && username != "" {
			return username, nil
		}
	}

	// Fallback to standard claims in order of preference
	fallbackClaims := []string{"preferred_username", "sub", "email", "username", "name"}
	for _, claim := range fallbackClaims {
		if val, ok := claims[claim]; ok {
			if username, ok := val.(string); ok && username != "" {
				return username, nil
			}
		}
	}

	return "", errors.New("username not found in JWT claims")
}

// extractRoles extracts roles from JWT claims
func extractRoles(claims jwt.MapClaims) []string {
	if val, ok := extractClaimValue(claims, setting.JWT.RolesClaim); ok {
		// Handle array of strings
		if roles, ok := val.([]interface{}); ok {
			result := make([]string, 0, len(roles))
			for _, role := range roles {
				if roleStr, ok := role.(string); ok {
					result = append(result, roleStr)
				}
			}
			return result
		}

		// Handle single string (comma-separated or single value)
		if roleStr, ok := val.(string); ok {
			if strings.Contains(roleStr, ",") {
				parts := strings.Split(roleStr, ",")
				result := make([]string, 0, len(parts))
				for _, part := range parts {
					if trimmed := strings.TrimSpace(part); trimmed != "" {
						result = append(result, trimmed)
					}
				}
				return result
			}
			return []string{roleStr}
		}
	}

	return []string{}
}

// validateJWTToken validates the JWT token and returns the claims
func (j *JWT) validateJWTToken(tokenString string) (jwt.MapClaims, error) {
	if !setting.JWT.Enabled {
		return nil, errors.New("JWT authentication is not enabled")
	}

	client := getJWKSClient()
	if client == nil {
		return nil, errors.New("JWKS client not initialized")
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the key ID from the token header
		kidInterface, ok := token.Header["kid"]
		if ok {
			// Kid is present, use it to fetch the specific key
			kid, ok := kidInterface.(string)
			if !ok {
				return nil, errors.New("invalid 'kid' header type")
			}

			// Fetch the public key from JWKS
			key, err := client.GetKey(kid)
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}

			return key, nil
		}

		// Kid is not present, try all keys from JWKS
		// This is normal behavior for some IdPs like Teleport
		// We'll return a special marker error to indicate we should try all keys
		// The actual key fetching and validation happens in the fallback handler below
		return nil, errors.New("token missing 'kid' header - will try all keys")
	})

	// If we got the special error about missing kid, try all keys
	if err != nil && strings.Contains(err.Error(), "token missing 'kid' header - will try all keys") {
		keys, keysErr := client.GetAllKeys()
		if keysErr != nil {
			return nil, fmt.Errorf("failed to get JWKS keys: %w", keysErr)
		}

		// Try parsing with each key
		var lastErr error
		for _, key := range keys {
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return key, nil
			})

			if err == nil && token.Valid {
				// Successfully validated with this key
				break
			}
			lastErr = err
		}

		// If still error after trying all keys, return the last error
		if err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("failed to validate token with any key from JWKS: %w", lastErr)
			}
			return nil, fmt.Errorf("failed to validate token with any key from JWKS: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid JWT claims")
	}

	// Validate issuer if configured
	if !setting.JWT.SkipIssuerCheck {
		if iss, ok := claims["iss"].(string); ok {
			if iss != setting.JWT.Issuer {
				return nil, fmt.Errorf("invalid issuer: %s (expected %s)", iss, setting.JWT.Issuer)
			}
		} else {
			return nil, errors.New("issuer claim missing")
		}
	}

	// Validate audience if configured
	if !setting.JWT.SkipAudienceCheck {
		validAudience := false

		// Audience can be string or array
		if aud, ok := claims["aud"].(string); ok {
			for _, expected := range setting.JWT.Audience {
				if aud == expected {
					validAudience = true
					break
				}
			}
		} else if audArray, ok := claims["aud"].([]interface{}); ok {
			for _, audInterface := range audArray {
				if aud, ok := audInterface.(string); ok {
					for _, expected := range setting.JWT.Audience {
						if aud == expected {
							validAudience = true
							break
						}
					}
				}
				if validAudience {
					break
				}
			}
		}

		if !validAudience {
			return nil, fmt.Errorf("invalid audience in JWT token (expected one of %v)", setting.JWT.Audience)
		}
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, errors.New("JWT token has expired")
		}
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Unix(int64(nbf), 0).After(time.Now()) {
			return nil, errors.New("JWT token not yet valid")
		}
	}

	return claims, nil
}

// extractEmail extracts email from JWT claims
func extractEmail(claims jwt.MapClaims) string {
	if val, ok := extractClaimValue(claims, setting.JWT.EmailClaim); ok {
		if email, ok := val.(string); ok && email != "" {
			return email
		}
	}
	if email, ok := claims["email"].(string); ok {
		return email
	}
	return ""
}

// extractFullName extracts full name from JWT claims
func extractFullName(claims jwt.MapClaims) string {
	if val, ok := extractClaimValue(claims, setting.JWT.FullNameClaim); ok {
		if name, ok := val.(string); ok && name != "" {
			return name
		}
	}
	if name, ok := claims["name"].(string); ok {
		return name
	}
	return ""
}

// autoCreateJWTUser creates a new user based on JWT claims
func autoCreateJWTUser(ctx context.Context, claims jwt.MapClaims, username string, roles []string) (*user_model.User, error) {
	// Extract email from claims or use default
	email := extractEmail(claims)
	if email == "" {
		email = username + setting.JWT.DefaultEmail
	}

	// Extract full name from claims
	fullName := extractFullName(claims)
	if fullName == "" {
		fullName = username
	}

	// Create user object
	user := &user_model.User{
		Name:               username,
		Email:              email,
		FullName:           fullName,
		Passwd:             "", // No password for JWT users
		IsActive:           setting.JWT.DefaultIsActive,
		IsAdmin:            setting.JWT.DefaultIsAdmin,
		LoginType:          auth_model.OAuth2, // Use OAuth2 login type for now
		LoginSource:        0,
		LoginName:          username,
		MustChangePassword: false,
	}

	// Create the user in the database
	if err := user_model.CreateUser(ctx, user, &user_model.Meta{}); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Add user to default organization if configured
	if setting.JWT.DefaultOrgID > 0 {
		if err := organization.AddOrgUser(ctx, setting.JWT.DefaultOrgID, user.ID); err != nil {
			log.Error("Failed to add user %s to default organization: %v", username, err)
		}
	}

	return user, nil
}

// syncUserTeamMemberships synchronizes user team memberships based on JWT roles
func syncUserTeamMemberships(ctx context.Context, user *user_model.User, jwtRoles []string) error {
	if setting.JWT.DefaultOrgID == 0 {
		return nil // No organization configured
	}

	// Build a set of teams the user should be in based on JWT roles
	desiredTeams := make(map[string]bool)
	for _, role := range jwtRoles {
		if teams, ok := setting.JWT.RoleToTeamMapping[role]; ok {
			for _, team := range teams {
				desiredTeams[strings.ToLower(team)] = true
			}
		}
	}

	if len(desiredTeams) == 0 {
		return nil // No team mappings configured
	}

	// Get all teams in the organization
	orgTeams, _, err := organization.SearchTeam(ctx, &organization.SearchTeamOptions{
		OrgID: setting.JWT.DefaultOrgID,
	})
	if err != nil {
		return fmt.Errorf("failed to get organization teams: %w", err)
	}

	// Add user to teams based on role mapping
	for _, team := range orgTeams {
		shouldBeInTeam := desiredTeams[strings.ToLower(team.Name)]
		isInTeam := team.IsMember(ctx, user.ID)

		if shouldBeInTeam && !isInTeam {
			// Add user to team
			if err := org_service.AddTeamMember(ctx, team, user); err != nil {
				log.Error("Failed to add user %s to team %s: %v", user.Name, team.Name, err)
			} else {
				log.Info("Added user %s to team %s based on JWT role", user.Name, team.Name)
			}
		} else if !shouldBeInTeam && isInTeam && !team.IsOwnerTeam() {
			// TODO: Optional feature to remove user from teams they shouldn't be in
			// This is commented out by default to be less destructive and avoid
			// accidentally removing manual team assignments.
			// if err := org_service.RemoveTeamMember(ctx, team, user); err != nil {
			//     log.Error("Failed to remove user %s from team %s: %v", user.Name, team.Name, err)
			// }
		}
	}

	return nil
}

// Verify extracts the user from the JWT token and returns the corresponding user object.
// Returns nil if verification fails.
func (j *JWT) Verify(req *http.Request, w http.ResponseWriter, store DataStore, sess SessionStore) (*user_model.User, error) {
	// Skip if JWT is not enabled
	if !setting.JWT.Enabled {
		return nil, nil
	}

	// Extract token from request
	tokenString, ok := parseJWTToken(req)
	if !ok {
		return nil, nil
	}

	// JWT tokens should have exactly 2 dots (header.payload.signature)
	if strings.Count(tokenString, ".") != 2 {
		return nil, nil
	}

	// Validate the token
	claims, err := j.validateJWTToken(tokenString)
	if err != nil {
		log.Trace("JWT Authentication: Failed to validate token: %v", err)
		return nil, fmt.Errorf("JWT authentication failed: %w", err)
	}

	// Extract username from claims
	username, err := extractUsername(claims)
	if err != nil {
		log.Error("JWT Authentication: Failed to extract username: %v", err)
		return nil, fmt.Errorf("failed to extract username from JWT: %w", err)
	}

	// Extract roles from claims
	roles := extractRoles(claims)

	// Get the user by username
	user, err := user_model.GetUserByName(req.Context(), username)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			// Auto-registration if enabled
			if setting.JWT.AutoRegister {
				user, err = autoCreateJWTUser(req.Context(), claims, username, roles)
				if err != nil {
					log.Error("JWT Authentication: Failed to auto-create user %s: %v", username, err)
					return nil, fmt.Errorf("failed to create user: %w", err)
				}
				log.Info("JWT Authentication: Auto-created user %s (ID: %d)", user.Name, user.ID)
			} else {
				log.Error("JWT Authentication: User %s does not exist and auto-registration is disabled", username)
				return nil, user_model.ErrUserNotExist{Name: username}
			}
		} else {
			log.Error("JWT Authentication: Failed to get user: %v", err)
			return nil, err
		}
	}

	// Sync team memberships based on roles (both for new and existing users)
	if setting.JWT.AutoRegister && len(roles) > 0 && setting.JWT.DefaultOrgID > 0 {
		if err := syncUserTeamMemberships(req.Context(), user, roles); err != nil {
			log.Warn("JWT Authentication: Failed to sync team memberships for user %s: %v", user.Name, err)
			// Don't fail authentication, just log the warning
		}
	}

	log.Trace("JWT Authentication: Authenticated user %s (ID: %d) with roles: %v", user.Name, user.ID, roles)

	// Store authentication metadata
	store.GetData()["IsJWTAuth"] = true
	store.GetData()["JWTUsername"] = username
	store.GetData()["JWTRoles"] = roles

	return user, nil
}
