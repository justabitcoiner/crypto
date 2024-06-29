import time, uuid
from joserfc import jwt
from crypto_key import SymmetricKey, AsymmetricKey


class DigitalSignature:
    @classmethod
    def sign(cls, key, alg, ttl=5 * 60) -> str:
        header = {"alg": alg}
        claims = {
            "iss": "justabitcoiner",
            "jti": uuid.uuid4().int,
            "exp": time.time() + ttl,
        }
        token_str = jwt.encode(header, claims, key)
        print("[x] token_str:", token_str)
        return token_str

    @classmethod
    def verify(cls, value, key, alg) -> bool:
        token_obj = jwt.decode(value, key, [alg])
        header = token_obj.header
        claims = token_obj.claims
        claims_registry = jwt.JWTClaimsRegistry()
        try:
            claims_registry.validate(claims)
            return True
        except Exception as e:
            return False


# Symmetric
alg = "HS256"
SymmetricKey.gen_key()
secret_key = SymmetricKey.get_key()
signed_msg = DigitalSignature.sign(secret_key, alg)
verify = DigitalSignature.verify(signed_msg, secret_key, alg)

# Asymmetric
alg = "RS256"
AsymmetricKey.gen_key()
private_key, public_key = AsymmetricKey.get_key()
signed_msg = DigitalSignature.sign(private_key, alg)
verify = DigitalSignature.verify(signed_msg, public_key, alg)
