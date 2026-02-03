// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"code.gitea.io/gitea/models/unittest"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/reqctx"
	"code.gitea.io/gitea/modules/setting"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuth(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	// Save original settings
	origEnabled := setting.JWT.Enabled
	origSecret := setting.JWT.Secret
	origIssuer := setting.JWT.Issuer
	origAudience := setting.JWT.Audience
	origAlgorithm := setting.JWT.SigningAlgorithm
	origExpiration := setting.JWT.ExpirationTime

	// Restore original settings after test
	defer func() {
		setting.JWT.Enabled = origEnabled
		setting.JWT.Secret = origSecret
		setting.JWT.Issuer = origIssuer
		setting.JWT.Audience = origAudience
		setting.JWT.SigningAlgorithm = origAlgorithm
		setting.JWT.ExpirationTime = origExpiration
	}()

	// Configure JWT for testing
	setting.JWT.Enabled = true
	setting.JWT.Secret = "test-secret-key-for-jwt-authentication"
	setting.JWT.Issuer = "gitea-test"
	setting.JWT.Audience = []string{"gitea-test"}
	setting.JWT.SigningAlgorithm = "HS256"
	setting.JWT.ExpirationTime = 3600

	t.Run("Disabled JWT", func(t *testing.T) {
		setting.JWT.Enabled = false
		defer func() { setting.JWT.Enabled = true }()

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err)
	})

	t.Run("Valid JWT Token", func(t *testing.T) {
		// Get a test user
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		// Generate a valid token
		token, err := GenerateJWTToken(user.ID, user.Name)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Create request with token
		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.NoError(t, err)
		assert.NotNil(t, authUser)
		assert.Equal(t, user.ID, authUser.ID)
		assert.Equal(t, user.Name, authUser.Name)
		assert.Equal(t, true, ds["IsJWTAuth"])
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err)
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		user, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, user)
		assert.Nil(t, err) // Invalid format should be ignored (not JWT)
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Create an expired token
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		now := time.Now()
		claims := &JWTClaims{
			UserID:   user.ID,
			Username: user.Name,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    setting.JWT.Issuer,
				Audience:  jwt.ClaimStrings(setting.JWT.Audience),
				ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired 1 hour ago
				NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(setting.JWT.Secret))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		now := time.Now()
		claims := &JWTClaims{
			UserID:   user.ID,
			Username: user.Name,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "wrong-issuer",
				Audience:  jwt.ClaimStrings(setting.JWT.Audience),
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(setting.JWT.Secret))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer")
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		now := time.Now()
		claims := &JWTClaims{
			UserID:   user.ID,
			Username: user.Name,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    setting.JWT.Issuer,
				Audience:  jwt.ClaimStrings([]string{"wrong-audience"}),
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(setting.JWT.Secret))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience")
	})

	t.Run("Wrong Signing Key", func(t *testing.T) {
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		now := time.Now()
		claims := &JWTClaims{
			UserID:   user.ID,
			Username: user.Name,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    setting.JWT.Issuer,
				Audience:  jwt.ClaimStrings(setting.JWT.Audience),
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("wrong-secret-key"))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
	})

	t.Run("Non-existent User", func(t *testing.T) {
		now := time.Now()
		claims := &JWTClaims{
			UserID:   999999, // Non-existent user
			Username: "nonexistent",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    setting.JWT.Issuer,
				Audience:  jwt.ClaimStrings(setting.JWT.Audience),
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(setting.JWT.Secret))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
		assert.True(t, user_model.IsErrUserNotExist(err))
	})

	t.Run("Username Mismatch", func(t *testing.T) {
		user, err := user_model.GetUserByID(unittest.DefaultContext, 1)
		assert.NoError(t, err)

		now := time.Now()
		claims := &JWTClaims{
			UserID:   user.ID,
			Username: "wrong-username",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    setting.JWT.Issuer,
				Audience:  jwt.ClaimStrings(setting.JWT.Audience),
				ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(now),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(setting.JWT.Secret))
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		ds := make(reqctx.ContextData)

		jwtAuth := &JWT{}
		authUser, err := jwtAuth.Verify(req, w, ds, nil)

		assert.Nil(t, authUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mismatch")
	})
}

func TestGenerateJWTToken(t *testing.T) {
	// Save original settings
	origEnabled := setting.JWT.Enabled
	origSecret := setting.JWT.Secret
	origIssuer := setting.JWT.Issuer
	origAudience := setting.JWT.Audience
	origAlgorithm := setting.JWT.SigningAlgorithm
	origExpiration := setting.JWT.ExpirationTime

	// Restore original settings after test
	defer func() {
		setting.JWT.Enabled = origEnabled
		setting.JWT.Secret = origSecret
		setting.JWT.Issuer = origIssuer
		setting.JWT.Audience = origAudience
		setting.JWT.SigningAlgorithm = origAlgorithm
		setting.JWT.ExpirationTime = origExpiration
	}()

	t.Run("JWT Disabled", func(t *testing.T) {
		setting.JWT.Enabled = false

		token, err := GenerateJWTToken(1, "testuser")
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("No Secret Configured", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.Secret = ""

		token, err := GenerateJWTToken(1, "testuser")
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "secret is not configured")
	})

	t.Run("HS256 Algorithm", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.Secret = "test-secret"
		setting.JWT.Issuer = "gitea-test"
		setting.JWT.Audience = []string{"gitea-test"}
		setting.JWT.SigningAlgorithm = "HS256"
		setting.JWT.ExpirationTime = 3600

		token, err := GenerateJWTToken(1, "testuser")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify the token can be parsed
		parsedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(setting.JWT.Secret), nil
		})
		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		claims, ok := parsedToken.Claims.(*JWTClaims)
		assert.True(t, ok)
		assert.Equal(t, int64(1), claims.UserID)
		assert.Equal(t, "testuser", claims.Username)
		assert.Equal(t, setting.JWT.Issuer, claims.Issuer)
	})

	t.Run("HS384 Algorithm", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.Secret = "test-secret"
		setting.JWT.SigningAlgorithm = "HS384"

		token, err := GenerateJWTToken(1, "testuser")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("HS512 Algorithm", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.Secret = "test-secret"
		setting.JWT.SigningAlgorithm = "HS512"

		token, err := GenerateJWTToken(1, "testuser")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("Unsupported Algorithm", func(t *testing.T) {
		setting.JWT.Enabled = true
		setting.JWT.Secret = "test-secret"
		setting.JWT.SigningAlgorithm = "RS256"

		token, err := GenerateJWTToken(1, "testuser")
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "unsupported")
	})
}

func TestJWTName(t *testing.T) {
	jwtAuth := &JWT{}
	assert.Equal(t, "jwt", jwtAuth.Name())
}
