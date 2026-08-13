# Token characterization — provider: node-oidc

Columns: ID Token vs access token(s). AC = authorization_code flow, CC = client_credentials grant. Decoded WITHOUT signature verification. known client_id (auth-code) = 'test-auth-code'.
A row where the access-token column carries a value the ID-token column lacks (or vice-versa) is a candidate F-07 discriminator.

| field                      | ID Token                | AC Access Token              | CC Access Token                 |
| -------------------------- | ----------------------- | ---------------------------- | ------------------------------- |
| format                     | jwt                     | jwt                          | jwt                             |
| header.typ                 | (absent)                | 'at+jwt'                     | 'at+jwt'                        |
| header.alg                 | 'RS256'                 | 'RS256'                      | 'RS256'                         |
| header.kid                 | 'rsa-sig-key'           | 'rsa-sig-key'                | 'rsa-sig-key'                   |
| iss                        | 'http://localhost:9010' | 'http://localhost:9010'      | 'http://localhost:9010'         |
| sub                        | 'test-user'             | 'test-user'                  | 'test-client-credentials'       |
| aud                        | 'test-auth-code'        | 'urn:test:api'               | 'urn:test:api'                  |
| aud == client_id?          | yes                     | no                           | no                              |
| azp                        | (absent)                | (absent)                     | (absent)                        |
| client_id (claim present?) | no                      | yes ('test-auth-code')       | yes ('test-client-credentials') |
| scope (claim present?)     | no                      | yes ('openid profile email') | yes ('openid')                  |
| scp (claim present?)       | no                      | no                           | no                              |
| nonce (present?)           | no                      | no                           | no                              |
| at_hash (present?)         | no                      | no                           | no                              |
| c_hash (present?)          | no                      | no                           | no                              |
| exp                        | 1786062795              | 1786062795                   | 1786062795                      |
| iat                        | 1786062495              | 1786062495                   | 1786062495                      |
