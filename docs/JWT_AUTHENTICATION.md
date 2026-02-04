# JWT Authentication Configuration

Gitea supports JWT (JSON Web Token) authentication for both API access and web UI. This allows integration with external identity providers (IdP) through reverse proxy authentication patterns.

## Overview

JWT authentication in Gitea:
- Validates tokens issued by external identity providers
- Works for both API endpoints and web UI access
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

### Example 5: Teleport Application Access

Teleport is a unified access plane that can act as an application proxy, automatically adding JWT tokens to forwarded requests.

```ini
[jwt]
ENABLED = true
HEADER_NAME = Teleport-Jwt-Assertion
JWKS_URL = https://your-teleport-proxy.example.com/.well-known/jwks.json
ISSUER = https://your-teleport-proxy.example.com
AUDIENCE = gitea
USERNAME_CLAIM = username
ROLES_CLAIM = roles
```

**Teleport Configuration** (`teleport.yaml`):

```yaml
app_service:
  enabled: true
  apps:
  - name: "gitea"
    uri: "http://gitea-internal:3000"
    public_addr: "gitea.example.com"
    rewrite:
      headers:
      - "Teleport-Jwt-Assertion: {{internal.jwt}}"
```

**Key Points for Teleport:**
- Teleport adds JWT tokens in the `Teleport-Jwt-Assertion` header by default
- The JWKS URL is typically `https://your-proxy:3080/.well-known/jwks.json`
- Username is in the `username` claim (not `sub` or `preferred_username`)
- Roles are provided in the `roles` claim as an array
- Ensure Gitea users exist with usernames matching Teleport users
- The issuer is your Teleport proxy address

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

3. **User Mapping**: Users must exist in Gitea before JWT authentication, unless auto-registration is enabled (see Auto-Registration section below).

4. **HTTPS Required**: In production, always use HTTPS for both Gitea and the JWKS URL.

5. **Header Security**: When using custom headers, ensure your reverse proxy strips these headers from external requests.

## Auto-Registration

JWT authentication can automatically create users on their first login, eliminating the need for manual user creation.

### Configuration

Add the following to your `app.ini` file:

```ini
[jwt]
# ... existing JWT configuration ...

# Enable automatic user creation on first JWT login
AUTO_REGISTER = true

# Organization ID to add new users to (optional, 0 to disable)
DEFAULT_ORG_ID = 1

# Whether auto-created users are active by default
DEFAULT_IS_ACTIVE = true

# Whether auto-created users are admins by default (use with caution!)
DEFAULT_IS_ADMIN = false

# JWT claim containing the user's email (default: email)
EMAIL_CLAIM = email

# JWT claim containing the user's full name (default: name)
FULL_NAME_CLAIM = name

# Default email domain if email is not in JWT (e.g., @gitea.local)
DEFAULT_EMAIL = @gitea.local

# Role to team mapping (JSON format)
# Maps JWT roles to Gitea team names within the default organization
ROLE_TO_TEAM_MAPPING = {"admin": ["Owners"], "developer": ["Developers"], "viewer": ["Viewers"]}
```

### How It Works

When auto-registration is enabled:

1. **First Login**: When a user authenticates with a valid JWT token but doesn't exist in Gitea:
   - A new user is created with information from the JWT claims
   - Email is extracted from the configured email claim (or defaults to username + DEFAULT_EMAIL)
   - Full name is extracted from the configured full name claim (or defaults to username)
   - User is added to the default organization (if configured)
   - User is added to teams based on JWT role mappings (if configured)

2. **Subsequent Logins**: On each login:
   - Team memberships are synchronized based on current JWT roles
   - Users are added to teams they should be in based on their JWT roles
   - Users are NOT automatically removed from teams (to preserve manual assignments)

### Role-Based Team Membership

The `ROLE_TO_TEAM_MAPPING` setting maps JWT roles to Gitea team names using JSON format:

```ini
# Single role to single team
ROLE_TO_TEAM_MAPPING = {"developer": ["Developers"]}

# Multiple roles to multiple teams
ROLE_TO_TEAM_MAPPING = {"admin": ["Owners"], "developer": ["Developers", "Contributors"], "viewer": ["Viewers"]}

# Complex mappings
ROLE_TO_TEAM_MAPPING = {
  "gitea-admin": ["Owners"],
  "gitea-dev": ["Developers"],
  "gitea-read": ["Viewers"],
  "gitea-write": ["Contributors", "Developers"]
}
```

**Important Notes:**
- Team names are case-insensitive
- Teams must already exist in the configured organization
- Users are added to teams on each login (roles are synchronized)
- Users are NOT automatically removed from teams they shouldn't be in
- The "Owners" team is never automatically removed

### Example: Complete Auto-Registration Setup

```ini
[jwt]
ENABLED = true
JWKS_URL = https://idp.example.com/.well-known/jwks.json
USERNAME_CLAIM = preferred_username
ROLES_CLAIM = roles

# Auto-registration settings
AUTO_REGISTER = true
DEFAULT_ORG_ID = 1
DEFAULT_IS_ACTIVE = true
EMAIL_CLAIM = email
FULL_NAME_CLAIM = name
DEFAULT_EMAIL = @gitea.local

# Map JWT roles to Gitea teams
ROLE_TO_TEAM_MAPPING = {
  "gitea-admin": ["Owners"],
  "gitea-developer": ["Developers"],
  "gitea-viewer": ["Viewers"]
}
```

With this configuration:
- Users with the `gitea-admin` role in their JWT will be added to the "Owners" team
- Users with the `gitea-developer` role will be added to the "Developers" team
- Users with the `gitea-viewer` role will be added to the "Viewers" team
- Users can have multiple roles and will be added to multiple teams accordingly

### Security Considerations for Auto-Registration

1. **Default Admin**: Always keep `DEFAULT_IS_ADMIN = false` unless you trust all users from your IdP
2. **Email Validation**: Ensure your IdP provides valid email addresses, or configure a sensible DEFAULT_EMAIL
3. **Role Validation**: Carefully configure role-to-team mappings to avoid giving excessive permissions
4. **Organization Access**: Consider which organization new users should join (DEFAULT_ORG_ID)
5. **Active Status**: Set `DEFAULT_IS_ACTIVE = false` if you want to manually approve new users

## Troubleshooting

### JWT authentication not working

1. Check that `ENABLED = true` in the `[jwt]` section
2. Verify the JWKS_URL is accessible from your Gitea server
3. Check Gitea logs for JWT authentication errors
4. Verify the token contains the `kid` header
5. Ensure the user exists in Gitea with the username from the JWT claim

### User not found error

If auto-registration is disabled, the username extracted from the JWT token must match an existing Gitea user. You may need to:
- Enable auto-registration with `AUTO_REGISTER = true`
- Create users in Gitea beforehand
- Configure the correct `USERNAME_CLAIM` to match your user directory
- Ensure username normalization matches between IdP and Gitea

### Auto-registration not working

If users are not being created automatically:
1. Verify `AUTO_REGISTER = true` in the `[jwt]` section
2. Check Gitea logs for user creation errors
3. Ensure the JWT token contains valid email and name claims (or configure defaults)
4. Verify the username from JWT is valid for Gitea (alphanumeric, dash, underscore only)
5. Check if email conflicts with existing users

### Team synchronization not working

If users are not being added to teams:
1. Verify `DEFAULT_ORG_ID` is set to a valid organization ID
2. Ensure `ROLE_TO_TEAM_MAPPING` is valid JSON
3. Check that teams exist in the configured organization
4. Verify role names in the mapping match roles in JWT tokens (case-sensitive)
5. Check Gitea logs for team synchronization errors

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

# Auto-registration settings
GITEA__jwt__AUTO_REGISTER=true
GITEA__jwt__DEFAULT_ORG_ID=1
GITEA__jwt__DEFAULT_IS_ACTIVE=true
GITEA__jwt__DEFAULT_IS_ADMIN=false
GITEA__jwt__EMAIL_CLAIM=email
GITEA__jwt__FULL_NAME_CLAIM=name
GITEA__jwt__DEFAULT_EMAIL=@gitea.local
GITEA__jwt__ROLE_TO_TEAM_MAPPING='{"admin": ["Owners"], "developer": ["Developers"]}'
```

## API and Web UI Usage

Once configured, JWT tokens can be used to authenticate both API requests and web UI access:

### API Authentication

```bash
# Using Authorization header (default)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://gitea.example.com/api/v1/user

# Using custom header
curl -H "X-JWT-Token: YOUR_JWT_TOKEN" \
  https://gitea.example.com/api/v1/user
```

### Web UI Authentication

When accessing the web UI through a browser, the JWT token should be passed via the configured header (typically through a reverse proxy). The reverse proxy adds the JWT token to requests before forwarding them to Gitea.

**Example with reverse proxy:**
- User accesses `https://gitea.example.com` through the reverse proxy
- Reverse proxy authenticates the user with your IdP
- Reverse proxy adds JWT token to the request header
- Gitea validates the token and grants access to the web UI

This enables seamless single sign-on (SSO) experience where users authenticate once with your IdP and gain access to both the Gitea web interface and API.

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
