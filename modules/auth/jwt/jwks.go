// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"code.gitea.io/gitea/modules/log"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (RSA, EC, etc.)
	Use string `json:"use"` // Public key use (sig, enc)
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSClient manages fetching and caching of JWKS
type JWKSClient struct {
	jwksURL    string
	keys       map[string]interface{} // map of kid -> public key
	lastFetch  time.Time
	cacheTTL   time.Duration
	mu         sync.RWMutex
	httpClient *http.Client
}

// NewJWKSClient creates a new JWKS client
func NewJWKSClient(jwksURL string) *JWKSClient {
	return &JWKSClient{
		jwksURL: jwksURL,
		keys:    make(map[string]interface{}),
		cacheTTL: 1 * time.Hour, // Cache keys for 1 hour
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetKey returns the public key for the given key ID
func (c *JWKSClient) GetKey(kid string) (interface{}, error) {
	// Try to get from cache first
	c.mu.RLock()
	if key, ok := c.keys[kid]; ok && time.Since(c.lastFetch) < c.cacheTTL {
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()

	// Fetch keys if not in cache or cache expired
	if err := c.fetchKeys(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Try again after fetching
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
}

// fetchKeys fetches and parses the JWKS from the configured URL
func (c *JWKSClient) fetchKeys() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if another goroutine already fetched recently
	if time.Since(c.lastFetch) < 10*time.Second {
		return nil
	}

	log.Trace("Fetching JWKS from %s", c.jwksURL)

	resp, err := c.httpClient.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Parse and store keys
	newKeys := make(map[string]interface{})
	for _, jwk := range jwks.Keys {
		key, err := parseJWK(jwk)
		if err != nil {
			log.Warn("Failed to parse JWK with kid '%s': %v", jwk.Kid, err)
			continue
		}
		newKeys[jwk.Kid] = key
	}

	if len(newKeys) == 0 {
		return errors.New("no valid keys found in JWKS")
	}

	c.keys = newKeys
	c.lastFetch = time.Now()
	log.Trace("Successfully fetched %d keys from JWKS", len(newKeys))

	return nil
}

// parseJWK converts a JWK to a public key
func parseJWK(jwk JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// parseRSAKey parses an RSA JWK to an RSA public key
func parseRSAKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode the modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode the exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	
	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	// Validate the key
	if err := validateRSAPublicKey(pubKey); err != nil {
		return nil, fmt.Errorf("invalid RSA public key: %w", err)
	}

	return pubKey, nil
}

// validateRSAPublicKey performs basic validation on an RSA public key
func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key.N == nil {
		return errors.New("modulus is nil")
	}
	if key.E < 2 {
		return errors.New("invalid exponent")
	}
	if key.N.BitLen() < 2048 {
		return errors.New("key size is too small (minimum 2048 bits)")
	}
	
	// Try to marshal and unmarshal to ensure it's valid
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	
	_, err = x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse marshaled key: %w", err)
	}
	
	return nil
}

// RefreshKeys forces a refresh of the JWKS cache
func (c *JWKSClient) RefreshKeys() error {
	c.mu.Lock()
	c.lastFetch = time.Time{} // Reset last fetch time to force refresh
	c.mu.Unlock()
	return c.fetchKeys()
}
