// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	user_model "code.gitea.io/gitea/models/user"
	jwtutil "code.gitea.io/gitea/modules/auth/jwt"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

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
		if !ok {
			return nil, errors.New("token missing 'kid' header")
		}
		
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
	})

	if err != nil {
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
			// Use generic error message to avoid user enumeration
			log.Error("JWT Authentication: User lookup failed")
			return nil, user_model.ErrUserNotExist{Name: username}
		}
		log.Error("JWT Authentication: Failed to get user: %v", err)
		return nil, err
	}

	log.Trace("JWT Authentication: Authenticated user %s (ID: %d) with roles: %v", user.Name, user.ID, roles)
	
	// Store authentication metadata
	store.GetData()["IsJWTAuth"] = true
	store.GetData()["JWTUsername"] = username
	store.GetData()["JWTRoles"] = roles
	
	return user, nil
}
