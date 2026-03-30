import { generateKeyPair, exportJWK } from "jose";
import Provider from "oidc-provider";

const PORT = parseInt(process.env.PORT || "9010", 10);
const ISSUER = process.env.ISSUER || `http://localhost:${PORT}`;

// --- Key Generation ---

async function generateKeys() {
  const { publicKey: rsaPub, privateKey: rsaPriv } = await generateKeyPair(
    "RS256",
    { extractable: true },
  );
  const rsaJwk = {
    ...(await exportJWK(rsaPriv)),
    kid: "rsa-sig-key",
    use: "sig",
    alg: "RS256",
  };

  const { publicKey: ecPub, privateKey: ecPriv } = await generateKeyPair(
    "ES256",
    { extractable: true },
  );
  const ecJwk = {
    ...(await exportJWK(ecPriv)),
    kid: "ec-sig-key",
    use: "sig",
    alg: "ES256",
  };

  return [rsaJwk, ecJwk];
}

// --- Static Account Store ---

const ACCOUNTS = {
  "test-user": {
    sub: "test-user",
    email: "test@example.com",
    email_verified: true,
    name: "Test User",
    given_name: "Test",
    family_name: "User",
  },
};

function findAccount(ctx, id) {
  const account = ACCOUNTS[id];
  if (!account) return undefined;
  return {
    accountId: id,
    async claims(use, scope) {
      return { sub: id, ...account };
    },
  };
}

// --- Provider Configuration ---

async function startProvider() {
  const jwks = { keys: await generateKeys() };

  const configuration = {
    // Static clients
    clients: [
      {
        client_id: "test-client-credentials",
        client_secret: "test-client-credentials-secret",
        grant_types: ["client_credentials"],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-auth-code",
        client_secret: "test-auth-code-secret",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: ["http://localhost:8080/callback"],
        scope: "openid profile email offline_access api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-device",
        client_secret: "test-device-secret",
        grant_types: [
          "urn:ietf:params:oauth:grant-type:device_code",
          "refresh_token",
        ],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-token-exchange",
        client_secret: "test-token-exchange-secret",
        grant_types: ["urn:ietf:params:oauth:grant-type:token-exchange"],
        response_types: [],
        scope: "openid api",
        token_endpoint_auth_method: "client_secret_basic",
      },
      {
        client_id: "test-fapi",
        client_secret: "test-fapi-secret",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        redirect_uris: ["http://localhost:8080/callback"],
        scope: "openid profile email api",
        token_endpoint_auth_method: "client_secret_basic",
      },
    ],

    // JWKS
    jwks,

    // Features
    features: {
      introspection: { enabled: true },
      revocation: { enabled: true },
      deviceFlow: {
        enabled: true,
        charset: "digits",
        userCodeInputSource: async (ctx, form, out, err) => {
          ctx.body = `<!DOCTYPE html><html><body>
            <h1>Device Login</h1>
            <form method="POST" action="${ctx.oidc.urlFor("code_verification")}">
              ${form}
              <input type="text" name="user_code" placeholder="Enter code">
              <button type="submit">Submit</button>
            </form>
          </body></html>`;
        },
      },
      clientCredentials: { enabled: true },
      dPoP: { enabled: true },
      pushedAuthorizationRequests: { enabled: true },
      requestObjects: {
        request: true,
      },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => undefined,
        getResourceServerInfo: (ctx, resourceIndicator) => ({
          scope: "openid profile email api",
          accessTokenFormat: "jwt",
          accessTokenTTL: 300,
          jwt: {
            sign: { alg: "RS256" },
          },
        }),
        useGrantedResource: () => true,
      },
      devInteractions: { enabled: true },
    },

    // Custom claims in access tokens (Descope-style multi-tenant claims)
    extraTokenClaims: async (ctx, token) => {
      if (token.kind === "AccessToken" || token.kind === "ClientCredentials") {
        return {
          dct: "test-tenant-1",
          tenants: {
            "test-tenant-1": {
              roles: ["admin"],
              permissions: ["projects.create", "projects.read"],
            },
            "test-tenant-2": {
              roles: ["viewer"],
              permissions: ["projects.read"],
            },
          },
        };
      }
      return {};
    },

    // Account lookup
    findAccount,

    // Scopes
    scopes: ["openid", "profile", "email", "offline_access", "api"],

    // Short TTLs for test speed
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      ClientCredentials: 300,
      DeviceCode: 300,
      Grant: 600,
      IdToken: 300,
      Interaction: 600,
      RefreshToken: 600,
      Session: 900,
    },

    // Claims mapping
    claims: {
      openid: ["sub"],
      profile: ["name", "given_name", "family_name"],
      email: ["email", "email_verified"],
    },

    // Cookie keys for session management
    cookies: {
      keys: ["test-fixture-cookie-key-1", "test-fixture-cookie-key-2"],
    },

    // Allow HTTP for local testing
    enabledJWA: {
      authorizationSigningAlgValues: ["RS256", "ES256"],
    },
  };

  const provider = new Provider(ISSUER, configuration);

  // Allow HTTP (non-TLS) for local test fixture
  provider.proxy = true;

  // --- Register Token Exchange Grant (RFC 8693) ---

  const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
  const parameters = new Set([
    "subject_token",
    "subject_token_type",
    "audience",
    "scope",
    "requested_token_type",
    "actor_token",
    "actor_token_type",
  ]);

  provider.registerGrantType(
    grantType,
    async function tokenExchangeHandler(ctx, next) {
      const {
        oidc: {
          params: {
            subject_token: subjectToken,
            subject_token_type: subjectTokenType,
          },
          client,
        },
      } = ctx;

      // Validate required parameters
      if (!subjectToken || !subjectTokenType) {
        ctx.body = {
          error: "invalid_request",
          error_description:
            "subject_token and subject_token_type are required",
        };
        ctx.status = 400;
        return next();
      }

      // For test purposes: accept access tokens as subject tokens
      const validTokenTypes = [
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:jwt",
      ];
      if (!validTokenTypes.includes(subjectTokenType)) {
        ctx.body = {
          error: "invalid_request",
          error_description: "unsupported subject_token_type",
        };
        ctx.status = 400;
        return next();
      }

      // Issue a new access token
      const AccessToken = provider.AccessToken;
      const at = new AccessToken({
        accountId: "test-user",
        client,
        scope: ctx.oidc.params.scope || "openid",
        grantId: ctx.oidc.uid,
      });

      const value = await at.save();
      const expiresIn = at.expiration;

      ctx.body = {
        access_token: value,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: expiresIn,
        scope: at.scope,
      };

      await next();
    },
    parameters,
  );

  // Start listening
  provider.listen(PORT, () => {
    console.log(
      `node-oidc-provider test fixture listening on ${ISSUER} (port ${PORT})`,
    );
    console.log(`Discovery: ${ISSUER}/.well-known/openid-configuration`);
    console.log(`JWKS: ${ISSUER}/jwks`);
  });
}

startProvider().catch((err) => {
  console.error("Failed to start provider:", err);
  process.exit(1);
});
