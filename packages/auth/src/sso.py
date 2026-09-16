"""OIDC access-token validation. Tenant mapping remains server-side."""
from dataclasses import dataclass
import jwt


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    issuer: str
    email: str | None


class OIDCValidator:
    def __init__(self, *, issuer: str, audience: str, jwks_url: str,
                 algorithms=("RS256",)):
        self.issuer, self.audience = issuer, audience
        self.algorithms = tuple(algorithms)
        self.jwks = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)

    def validate(self, token: str) -> OIDCIdentity:
        key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(token,key.key,algorithms=self.algorithms,
                            audience=self.audience,issuer=self.issuer,
                            options={"require":["exp","iat","iss","aud","sub"]})
        return OIDCIdentity(str(claims["sub"]),str(claims["iss"]),claims.get("email"))
