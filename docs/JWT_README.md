# JWT Authentication for Gitea

This implementation adds JWT (JSON Web Token) authentication support to Gitea, allowing integration with external identity providers through reverse proxy authentication patterns.

## Features

✅ **JWKS Validation**: Validates JWT tokens using public keys from a JWKS (JSON Web Key Set) endpoint  
✅ **Configurable Header**: JWT tokens can be received from any HTTP header (not just Authorization)  
✅ **Flexible Claims**: Extract username and roles from configurable JWT claims with support for nested claims  
✅ **Multiple IdP Support**: Works with Auth0, Keycloak, Azure AD, and any OIDC-compliant identity provider  
✅ **Production Ready**: Includes key caching, comprehensive error handling, and security best practices  
✅ **Zero Breaking Changes**: Fully backward compatible with existing authentication methods  

## Quick Start

### 1. Configure Gitea

Add to `app.ini`:

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

### 2. Restart Gitea

```bash
sudo systemctl restart gitea
```

### 3. Test with a JWT Token

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://gitea.example.com/api/v1/user
```

## Documentation

- **[Quick Start Guide](QUICK_START_JWT.md)** - Get up and running in 5 minutes
- **[Full Documentation](JWT_AUTHENTICATION.md)** - Complete configuration reference and troubleshooting
- **[Configuration Examples](jwt-config-examples.ini)** - Ready-to-use examples for popular IdP providers

## Configuration Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `ENABLED` | Yes | `false` | Enable JWT authentication |
| `JWKS_URL` | Yes | - | URL to fetch public keys for validation |
| `HEADER_NAME` | No | `Authorization` | HTTP header containing the JWT token |
| `ISSUER` | No | `gitea` | Expected JWT issuer (can be skipped) |
| `AUDIENCE` | No | `gitea` | Expected JWT audience (can be skipped) |
| `USERNAME_CLAIM` | No | `preferred_username` | JWT claim containing username |
| `ROLES_CLAIM` | No | `roles` | JWT claim containing user roles |
| `SKIP_ISSUER_CHECK` | No | `false` | Skip issuer validation |
| `SKIP_AUDIENCE_CHECK` | No | `false` | Skip audience validation |

## Supported Identity Providers

### Keycloak
```ini
[jwt]
ENABLED = true
JWKS_URL = https://keycloak.example.com/realms/your-realm/protocol/openid-connect/certs
ISSUER = https://keycloak.example.com/realms/your-realm
USERNAME_CLAIM = preferred_username
```

### Auth0
```ini
[jwt]
ENABLED = true
JWKS_URL = https://your-tenant.auth0.com/.well-known/jwks.json
ISSUER = https://your-tenant.auth0.com/
USERNAME_CLAIM = email
```

### Azure AD (Microsoft Entra ID)
```ini
[jwt]
ENABLED = true
JWKS_URL = https://login.microsoftonline.com/common/discovery/v2.0/keys
ISSUER = https://login.microsoftonline.com/{tenant-id}/v2.0
USERNAME_CLAIM = preferred_username
```

### Teleport Application Access
```ini
[jwt]
ENABLED = true
HEADER_NAME = Teleport-Jwt-Assertion
JWKS_URL = https://your-teleport-proxy.example.com/.well-known/jwks.json
ISSUER = https://your-teleport-proxy.example.com
USERNAME_CLAIM = username
ROLES_CLAIM = roles
```

## How It Works

1. **Request arrives** with JWT token in configured header
2. **Token parsed** and `kid` (key ID) extracted from header
3. **Public key fetched** from JWKS URL (cached for 1 hour)
4. **Signature validated** using the public key
5. **Claims validated** (expiration, issuer, audience, etc.)
6. **Username extracted** from configured claim
7. **User authenticated** if all checks pass

## Architecture

```
┌─────────────────┐
│  Reverse Proxy  │
│   (Optional)    │
└────────┬────────┘
         │ JWT Token
         ▼
┌─────────────────┐
│     Gitea       │
│  ┌───────────┐  │
│  │    JWT    │  │
│  │   Auth    │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │   JWKS    │  │
│  │  Client   │  │
│  └─────┬─────┘  │
│        │        │
└────────┼────────┘
         │
         ▼
┌─────────────────┐
│   Identity      │
│   Provider      │
│   (JWKS URL)    │
└─────────────────┘
```

## Implementation Details

### Files Added

- `modules/setting/jwt.go` - JWT configuration settings
- `modules/auth/jwt/jwks.go` - JWKS client for fetching public keys
- `services/auth/jwt.go` - JWT authentication method implementation
- `services/auth/jwt_test.go` - Comprehensive unit tests
- `docs/JWT_AUTHENTICATION.md` - Full documentation
- `docs/jwt-config-examples.ini` - Configuration examples
- `docs/QUICK_START_JWT.md` - Quick start guide

### Files Modified

- `modules/setting/setting.go` - Register JWT settings loader
- `routers/api/v1/api.go` - Register JWT auth in API auth chain

### Key Features

**JWKS Client (`modules/auth/jwt/jwks.go`)**
- Fetches and caches public keys from JWKS endpoint
- Supports RSA keys (RS256/RS384/RS512)
- Automatic key refresh every hour
- Thread-safe with mutex protection
- Validates key format and size (minimum 2048 bits)

**JWT Authentication (`services/auth/jwt.go`)**
- Validates JWT signatures using JWKS public keys
- Extracts username from configurable claims
- Extracts roles from configurable claims
- Supports nested claim paths with dot notation
- Validates standard JWT claims (exp, nbf, iss, aud)
- Configurable header name for reverse proxy scenarios

## Testing

### Unit Tests

```bash
go test -tags="sqlite sqlite_unlock_notify" ./services/auth -run "TestJWT|TestExtract" -v
```

### Test Coverage

- JWT authentication with various configurations
- Claim extraction (simple and nested)
- Username extraction with fallbacks
- Roles extraction (array and string formats)
- Custom header name support
- Error handling scenarios

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production for both Gitea and JWKS URL
2. **Key Caching**: Public keys cached for 1 hour to reduce IdP load
3. **Token Validation**: Full validation of signature, expiration, issuer, audience
4. **User Mapping**: Users must exist in Gitea (no auto-provisioning)
5. **Header Injection**: When using custom headers, ensure reverse proxy strips them from external requests
6. **Minimum Key Size**: RSA keys must be at least 2048 bits

## Limitations

- **No Token Generation**: This implementation only validates tokens (no token generation)
- **RSA Only**: Currently supports RSA keys only (RS256/RS384/RS512), not EC keys
- **No Auto-Provisioning**: Users must be created in Gitea manually
- **No HMAC Support**: Only supports asymmetric algorithms (JWKS-based validation)

## Future Enhancements

- Support for EC (Elliptic Curve) keys (ES256/ES384/ES512)
- Automatic user provisioning from JWT claims
- Role-based access control using extracted roles
- Token refresh mechanism
- Multiple JWKS URLs support
- Custom claim validators

## Troubleshooting

See [Full Documentation](JWT_AUTHENTICATION.md#troubleshooting) for detailed troubleshooting steps.

Common issues:
- JWKS URL not accessible
- Token expired or not yet valid
- Issuer/audience mismatch
- User not found in Gitea
- Custom header not received

## Contributing

When contributing to JWT authentication:

1. Run tests: `go test -tags="sqlite sqlite_unlock_notify" ./services/auth -v`
2. Update documentation if adding new features
3. Maintain backward compatibility
4. Follow existing code style and patterns
5. Add tests for new functionality

## License

This implementation follows Gitea's license (MIT).

## Credits

Implemented following Gitea's existing authentication patterns and integrating cleanly with the current auth chain.
