// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http/httptest"
	"testing"

	"code.gitea.io/gitea/models/unittest"
	"code.gitea.io/gitea/modules/reqctx"
	"code.gitea.io/gitea/modules/setting"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuth(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	// Save original settings
	origEnabled := setting.JWT.Enabled
	origHeaderName := setting.JWT.HeaderName
	origJWKSURL := setting.JWT.JWKSURL

	// Restore original settings after test
	defer func() {
		setting.JWT.Enabled = origEnabled
		setting.JWT.HeaderName = origHeaderName
		setting.JWT.JWKSURL = origJWKSURL
	}()

	t.Run("Disabled JWT", func(t *testing.T) {
		setting.JWT.Enabled = false

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err)
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.JWKSURL = "https://example.com/jwks"

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err)
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.JWKSURL = "https://example.com/jwks"

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err) // Invalid format should be ignored (not JWT)
	})

	t.Run("Custom Header Name", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.HeaderName = "X-JWT-Token"
		setting.JWT.JWKSURL = "https://example.com/jwks"

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("X-JWT-Token", "token.value.here")
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		// This will fail validation but demonstrates header extraction
		user, err := jwtAuth.Verify(req, w, ds, nil)

		// Token extraction works, but validation fails (expected)
		assert.Nil(t, user)
		// Error is expected since we can't validate without proper JWKS
		assert.Error(t, err)
	})
}

func TestJWTName(t *testing.T) {
	jwtAuth := &JWT{}
	assert.Equal(t, "jwt", jwtAuth.Name())
}

func TestExtractClaimValue(t *testing.T) {
	claims := jwt.MapClaims{
		"username": "john.doe",
		"email":    "john@example.com",
		"user": map[string]interface{}{
			"id":   "12345",
			"name": "John Doe",
			"roles": []interface{}{
				"admin",
				"developer",
			},
		},
	}

	tests := []struct {
		name      string
		claimPath string
		expected  interface{}
		found     bool
	}{
		{
			name:      "Simple claim",
			claimPath: "username",
			expected:  "john.doe",
			found:     true,
		},
		{
			name:      "Nested claim",
			claimPath: "user.name",
			expected:  "John Doe",
			found:     true,
		},
		{
			name:      "Deep nested claim",
			claimPath: "user.id",
			expected:  "12345",
			found:     true,
		},
		{
			name:      "Non-existent claim",
			claimPath: "non.existent",
			expected:  nil,
			found:     false,
		},
		{
			name:      "Array claim",
			claimPath: "user.roles",
			expected:  []interface{}{"admin", "developer"},
			found:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := extractClaimValue(claims, tt.claimPath)
			assert.Equal(t, tt.found, found)
			if found {
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	// Save original setting
	origUsernameClaim := setting.JWT.UsernameClaim
	defer func() {
		setting.JWT.UsernameClaim = origUsernameClaim
	}()

	tests := []struct {
		name          string
		claims        jwt.MapClaims
		usernameClaim string
		expected      string
		expectError   bool
	}{
		{
			name: "Username from preferred_username",
			claims: jwt.MapClaims{
				"preferred_username": "john.doe",
			},
			usernameClaim: "preferred_username",
			expected:      "john.doe",
			expectError:   false,
		},
		{
			name: "Username from sub",
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			usernameClaim: "sub",
			expected:      "user123",
			expectError:   false,
		},
		{
			name: "Username from email",
			claims: jwt.MapClaims{
				"email": "john@example.com",
			},
			usernameClaim: "email",
			expected:      "john@example.com",
			expectError:   false,
		},
		{
			name: "Username from nested claim",
			claims: jwt.MapClaims{
				"user": map[string]interface{}{
					"name": "john.doe",
				},
			},
			usernameClaim: "user.name",
			expected:      "john.doe",
			expectError:   false,
		},
		{
			name: "Fallback to sub when configured claim missing",
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			usernameClaim: "preferred_username",
			expected:      "user123",
			expectError:   false,
		},
		{
			name:          "No username claim found",
			claims:        jwt.MapClaims{},
			usernameClaim: "preferred_username",
			expected:      "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setting.JWT.UsernameClaim = tt.usernameClaim

			username, err := extractUsername(tt.claims)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, username)
			}
		})
	}
}

func TestExtractRoles(t *testing.T) {
	// Save original setting
	origRolesClaim := setting.JWT.RolesClaim
	defer func() {
		setting.JWT.RolesClaim = origRolesClaim
	}()

	tests := []struct {
		name       string
		claims     jwt.MapClaims
		rolesClaim string
		expected   []string
	}{
		{
			name: "Roles as array",
			claims: jwt.MapClaims{
				"roles": []interface{}{"admin", "developer"},
			},
			rolesClaim: "roles",
			expected:   []string{"admin", "developer"},
		},
		{
			name: "Roles as comma-separated string",
			claims: jwt.MapClaims{
				"roles": "admin,developer,user",
			},
			rolesClaim: "roles",
			expected:   []string{"admin", "developer", "user"},
		},
		{
			name: "Roles as single string",
			claims: jwt.MapClaims{
				"roles": "admin",
			},
			rolesClaim: "roles",
			expected:   []string{"admin"},
		},
		{
			name: "Roles from nested claim",
			claims: jwt.MapClaims{
				"user": map[string]interface{}{
					"groups": []interface{}{"developers", "admins"},
				},
			},
			rolesClaim: "user.groups",
			expected:   []string{"developers", "admins"},
		},
		{
			name:       "No roles claim",
			claims:     jwt.MapClaims{},
			rolesClaim: "roles",
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setting.JWT.RolesClaim = tt.rolesClaim

			roles := extractRoles(tt.claims)
			assert.Equal(t, tt.expected, roles)
		})
	}
}
