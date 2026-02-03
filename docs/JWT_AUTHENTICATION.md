# JWT Authentication Configuration

Gitea supports JWT (JSON Web Token) authentication for API access. This allows integration with external identity providers (IdP) through reverse proxy authentication patterns.

## Overview

JWT authentication in Gitea:
- Validates tokens issued by external identity providers
- Uses JWKS (JSON Web Key Set) to fetch and cache public keys
- Supports configurable HTTP header for receiving JWT tokens
- Extracts username and roles from configurable JWT claims
- Works seamlessly with reverse proxy authentication setups

## Configuration

Add the following to your `app.ini` file:

```ini
[jwt]
; Enable JWT authentication
ENABLED = false

; HTTP header containing the JWT token (default: Authorization)
; For reverse proxy setups, this might be X-JWT-Token, X-Forwarded-Access-Token, etc.
HEADER_NAME = Authorization

; JWKS URL to fetch public keys for token validation (REQUIRED when JWT is enabled)
; Example: https://your-idp.com/.well-known/jwks.json
JWKS_URL = https://your-idp.example.com/.well-known/jwks.json

; Expected issuer claim in JWT (optional, can be skipped)
ISSUER = https://your-idp.example.com

; Expected audience claim(s) in JWT (optional, can be skipped)
; Multiple audiences can be separated by commas
AUDIENCE = gitea,your-app

; Skip issuer validation (default: false)
; Set to true if you want to accept tokens from multiple issuers
SKIP_ISSUER_CHECK = false

; Skip audience validation (default: false)
; Set to true if you don't want to validate the audience claim
SKIP_AUDIENCE_CHECK = false

; JWT claim containing the username (default: preferred_username)
; Common values: sub, preferred_username, email, username, name
; Supports nested claims with dot notation: user.username
USERNAME_CLAIM = preferred_username

; JWT claim containing user roles (default: roles)
; Common values: roles, groups, authorities
; Supports nested claims with dot notation: user.roles
ROLES_CLAIM = roles
```

## Usage Examples

### Example 1: Auth0 Integration

```ini
[jwt]
ENABLED = true
HEADER_NAME = Authorization
JWKS_URL = https://your-tenant.auth0.com/.well-known/jwks.json
ISSUER = https://your-tenant.auth0.com/
AUDIENCE = your-api-identifier
USERNAME_CLAIM = email
ROLES_CLAIM = https://your-app/roles
```

### Example 2: Keycloak Integration

```ini
[jwt]
ENABLED = true
HEADER_NAME = Authorization
JWKS_URL = https://keycloak.example.com/realms/your-realm/protocol/openid-connect/certs
ISSUER = https://keycloak.example.com/realms/your-realm
AUDIENCE = gitea
USERNAME_CLAIM = preferred_username
ROLES_CLAIM = roles
```

### Example 3: Azure AD Integration

```ini
[jwt]
ENABLED = true
HEADER_NAME = Authorization
JWKS_URL = https://login.microsoftonline.com/common/discovery/v2.0/keys
ISSUER = https://login.microsoftonline.com/{tenant-id}/v2.0
AUDIENCE = api://your-app-id
USERNAME_CLAIM = preferred_username
ROLES_CLAIM = roles
```

### Example 4: Reverse Proxy with Custom Header

```ini
[jwt]
ENABLED = true
HEADER_NAME = X-JWT-Token
JWKS_URL = https://your-idp.example.com/.well-known/jwks.json
SKIP_ISSUER_CHECK = true
SKIP_AUDIENCE_CHECK = true
USERNAME_CLAIM = sub
ROLES_CLAIM = groups
```

## How It Works

1. **Request arrives**: Gitea receives an HTTP request with a JWT token in the configured header
2. **Token extraction**: The JWT token is extracted from the specified header
3. **Key fetching**: The token's `kid` (key ID) is used to fetch the corresponding public key from the JWKS URL
4. **Validation**: The token signature is validated using the public key
5. **Claims validation**: Issuer, audience, expiration, and other standard claims are validated
6. **User lookup**: Username is extracted from the configured claim and the user is looked up in Gitea
7. **Roles extraction**: Roles/groups are extracted and stored in the request context
8. **Authentication**: If all validations pass, the user is authenticated

## Token Format

The JWT token must:
- Have a valid signature verifiable with keys from the JWKS URL
- Include a `kid` (key ID) in the header
- Include standard claims: `exp` (expiration), `iat` (issued at), optionally `nbf` (not before)
- Include the configured username claim (e.g., `preferred_username`, `sub`, `email`)
- Optionally include the configured roles claim

Example JWT header:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-from-jwks"
}
```

Example JWT payload:
```json
{
  "iss": "https://your-idp.example.com",
  "sub": "user-id",
  "aud": "gitea",
  "exp": 1735689600,
  "iat": 1735686000,
  "preferred_username": "john.doe",
  "email": "john.doe@example.com",
  "roles": ["developer", "admin"]
}
```

## Security Considerations

1. **JWKS Caching**: Public keys are cached for 1 hour to reduce load on the IdP. Keys are automatically refreshed when expired.

2. **Token Validation**: All tokens are validated for:
   - Valid signature
   - Not expired
   - Not before time (if present)
   - Issuer (if not skipped)
   - Audience (if not skipped)

3. **User Mapping**: Users must exist in Gitea. JWT authentication does NOT automatically create users.

4. **HTTPS Required**: In production, always use HTTPS for both Gitea and the JWKS URL.

5. **Header Security**: When using custom headers, ensure your reverse proxy strips these headers from external requests.

## Troubleshooting

### JWT authentication not working

1. Check that `ENABLED = true` in the `[jwt]` section
2. Verify the JWKS_URL is accessible from your Gitea server
3. Check Gitea logs for JWT authentication errors
4. Verify the token contains the `kid` header
5. Ensure the user exists in Gitea with the username from the JWT claim

### User not found error

The username extracted from the JWT token must match an existing Gitea user. You may need to:
- Create users in Gitea beforehand
- Configure the correct `USERNAME_CLAIM` to match your user directory
- Ensure username normalization matches between IdP and Gitea

### Token validation fails

1. Verify the JWKS URL is correct and returns valid keys
2. Check that the `kid` in the token matches a key in the JWKS
3. Verify issuer and audience claims match your configuration
4. Check token expiration time

### Custom header not working

1. Ensure your reverse proxy is passing the JWT token in the configured header
2. Verify the header name matches exactly (case-sensitive)
3. For Authorization header, ensure "Bearer " prefix is included
4. For custom headers, the token should be the raw JWT without any prefix

## Environment Variables

All JWT settings can also be configured via environment variables:

```bash
GITEA__jwt__ENABLED=true
GITEA__jwt__HEADER_NAME=Authorization
GITEA__jwt__JWKS_URL=https://your-idp.example.com/.well-known/jwks.json
GITEA__jwt__ISSUER=https://your-idp.example.com
GITEA__jwt__AUDIENCE=gitea
GITEA__jwt__SKIP_ISSUER_CHECK=false
GITEA__jwt__SKIP_AUDIENCE_CHECK=false
GITEA__jwt__USERNAME_CLAIM=preferred_username
GITEA__jwt__ROLES_CLAIM=roles
```

## API Usage

Once configured, API requests can be authenticated using JWT tokens:

```bash
# Using Authorization header (default)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://gitea.example.com/api/v1/user

# Using custom header
curl -H "X-JWT-Token: YOUR_JWT_TOKEN" \
  https://gitea.example.com/api/v1/user
```

## Integration with Reverse Proxy

### Nginx Example

```nginx
location / {
    proxy_pass http://gitea:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Pass JWT token from upstream authentication
    proxy_set_header X-JWT-Token $http_authorization;
}
```

### Apache Example

```apache
<Location />
    ProxyPass http://gitea:3000/
    ProxyPassReverse http://gitea:3000/
    
    # Pass JWT token from upstream authentication
    RequestHeader set X-JWT-Token %{HTTP:Authorization}
</Location>
```

### Traefik Example

```yaml
http:
  middlewares:
    jwt-forward:
      headers:
        customRequestHeaders:
          X-JWT-Token: "Bearer YOUR_TOKEN_HERE"
  
  routers:
    gitea:
      rule: "Host(`gitea.example.com`)"
      service: gitea
      middlewares:
        - jwt-forward
  
  services:
    gitea:
      loadBalancer:
        servers:
          - url: "http://gitea:3000"
```
