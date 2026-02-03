# Quick Start Guide - JWT Authentication

This guide shows you how to quickly set up and test JWT authentication in Gitea.

## Prerequisites

1. Gitea installed and running
2. An external identity provider (IdP) with JWKS endpoint (e.g., Keycloak, Auth0, Azure AD)
3. Users created in both your IdP and Gitea with matching usernames

## Step 1: Configure Gitea

Edit your `app.ini` file and add:

```ini
[jwt]
ENABLED = true
HEADER_NAME = Authorization
JWKS_URL = https://your-idp.example.com/.well-known/jwks.json
ISSUER = https://your-idp.example.com
AUDIENCE = gitea
USERNAME_CLAIM = preferred_username
ROLES_CLAIM = roles
```

## Step 2: Restart Gitea

```bash
# Using systemd
sudo systemctl restart gitea

# Using docker
docker restart gitea

# Manual
./gitea web
```

## Step 3: Obtain a JWT Token

Get a JWT token from your identity provider. The method depends on your IdP:

### Keycloak Example (Using Resource Owner Password Flow)

**⚠️ Security Note**: The Resource Owner Password Credentials (ROPC) flow shown below is **NOT recommended for production** as it exposes user credentials directly to the client. For production use, prefer the Authorization Code flow with PKCE or Client Credentials flow.

```bash
# For testing/development only - NOT for production
curl -X POST "https://keycloak.example.com/realms/your-realm/protocol/openid-connect/token" \
  -d "client_id=your-client" \
  -d "client_secret=your-secret" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "grant_type=password" \
  | jq -r '.access_token'
```

### Auth0 Example (Using Client Credentials - Recommended)

```bash
# Client Credentials flow - suitable for machine-to-machine
curl -X POST "https://your-tenant.auth0.com/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "audience": "your-api-identifier",
    "grant_type": "client_credentials"
  }' \
  | jq -r '.access_token'
```

### Production Recommendation

For production environments, use one of these secure flows:
- **Authorization Code with PKCE**: For user-facing applications
- **Client Credentials**: For machine-to-machine authentication
- **Device Flow**: For devices without browsers

Consult your identity provider's documentation for implementing these flows.

## Step 4: Test the API

Use the JWT token to authenticate API requests:

```bash
# Store the token
export JWT_TOKEN="your-jwt-token-here"

# Test authentication
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://gitea.example.com/api/v1/user

# You should get your user information back
```

## Step 5: Verify in Logs

Check Gitea logs to confirm JWT authentication:

```bash
tail -f /var/log/gitea/gitea.log | grep JWT
```

You should see messages like:
```
[jwt] JWT authentication enabled with JWKS URL: https://your-idp.example.com/.well-known/jwks.json
JWT Authentication: Authenticated user john.doe (ID: 1) with roles: [admin developer]
```

## Troubleshooting

### Authentication fails

1. **Check JWKS URL is accessible**:
   ```bash
   curl https://your-idp.example.com/.well-known/jwks.json
   ```
   Should return a JSON with public keys

2. **Verify token is valid**:
   Decode the JWT at [jwt.io](https://jwt.io) and check:
   - Token is not expired (`exp` claim)
   - Has correct issuer (`iss` claim)
   - Has correct audience (`aud` claim)
   - Contains the username claim (e.g., `preferred_username`)

3. **Check user exists in Gitea**:
   The username from the JWT must match an existing Gitea user

4. **Enable debug logging**:
   ```ini
   [log]
   LEVEL = Trace
   ```

### User not found

The username extracted from JWT must exist in Gitea:

```bash
# Create user via Gitea admin interface or CLI
gitea admin user create --username john.doe --email john@example.com
```

### JWKS fetch fails

1. Ensure JWKS URL is accessible from Gitea server
2. Check firewall rules
3. Verify SSL certificates (use valid HTTPS)

## Example with curl and jq

Complete example to test JWT authentication:

```bash
#!/bin/bash

# Configuration
IDP_URL="https://your-idp.example.com"
GITEA_URL="https://gitea.example.com"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
USERNAME="testuser"
PASSWORD="testpass"

# Get JWT token from IdP
TOKEN=$(curl -s -X POST "${IDP_URL}/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"client_secret\": \"${CLIENT_SECRET}\",
    \"username\": \"${USERNAME}\",
    \"password\": \"${PASSWORD}\",
    \"grant_type\": \"password\"
  }" \
  | jq -r '.access_token')

echo "Got token: ${TOKEN:0:50}..."

# Test Gitea API
echo "Testing Gitea API..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "${GITEA_URL}/api/v1/user" \
  | jq .

# Test with custom header (if configured)
echo "Testing with custom header..."
curl -s -H "X-JWT-Token: $TOKEN" \
  "${GITEA_URL}/api/v1/user" \
  | jq .
```

## Integration with Reverse Proxy

### Nginx Example

```nginx
location / {
    proxy_pass http://gitea:3000;
    
    # Pass JWT from OAuth2 Proxy
    proxy_set_header X-JWT-Token $http_x_forwarded_access_token;
    
    # Or from Authorization header
    proxy_set_header Authorization $http_authorization;
}
```

### Traefik Example

```yaml
http:
  middlewares:
    jwt-forward:
      headers:
        customRequestHeaders:
          X-JWT-Token: "{{ .Request.Header.Get \"Authorization\" }}"
```

### Teleport Application Access

Teleport provides zero-trust access to applications with automatic JWT token injection. Here's how to set it up:

#### 1. Configure Teleport Application Service

Add to your Teleport configuration (`teleport.yaml`):

```yaml
app_service:
  enabled: true
  apps:
  - name: "gitea"
    uri: "http://gitea-internal.local:3000"
    public_addr: "gitea.example.com"
    # Teleport will inject JWT token in this header
    rewrite:
      headers:
      - "Teleport-Jwt-Assertion: {{internal.jwt}}"
```

#### 2. Configure Gitea

Add to your `app.ini`:

```ini
[jwt]
ENABLED = true
HEADER_NAME = Teleport-Jwt-Assertion
JWKS_URL = https://teleport-proxy.example.com/.well-known/jwks.json
ISSUER = https://teleport-proxy.example.com
AUDIENCE = gitea
USERNAME_CLAIM = username
ROLES_CLAIM = roles
```

#### 3. Access Gitea through Teleport

```bash
# Login to Teleport
tsh login --proxy=teleport-proxy.example.com

# List available apps
tsh apps ls

# Login to the Gitea app
tsh apps login gitea

# Access Gitea - Teleport will automatically inject JWT
curl https://gitea.example.com/api/v1/user

# Or use your browser - authentication is transparent
# Navigate to https://gitea.example.com
```

#### Key Benefits of Teleport Integration

- **Zero-trust access**: All access goes through Teleport with identity verification
- **Automatic JWT injection**: No need to manually manage tokens
- **Session recording**: All API calls can be audited through Teleport
- **Role-based access**: Teleport roles map directly to Gitea through JWT claims
- **Certificate-based**: Teleport uses short-lived certificates for additional security
- **Unified access**: Same login for SSH, Kubernetes, databases, and web apps

#### Teleport-specific Notes

- The JWKS endpoint is typically at `https://your-proxy:3080/.well-known/jwks.json`
- Teleport uses the `username` claim (not `sub` or `preferred_username`)
- Roles are in the `roles` claim as an array of Teleport role names
- Users must exist in both Teleport and Gitea with matching usernames
- Token expiration is controlled by Teleport (default: 12 hours)


## Next Steps

1. Review the [full documentation](JWT_AUTHENTICATION.md)
2. Check the [configuration examples](jwt-config-examples.ini)
3. Set up your production IdP integration
4. Configure user provisioning
5. Set up role-based access control (using the extracted roles)

## Security Checklist

- [ ] HTTPS enabled for both Gitea and IdP
- [ ] JWKS URL accessible only from Gitea server
- [ ] Reverse proxy strips JWT headers from external requests
- [ ] Token expiration configured appropriately in IdP
- [ ] Users provisioned in Gitea
- [ ] Logs monitored for auth failures
- [ ] Backup authentication method available
