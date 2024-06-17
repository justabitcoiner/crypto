from joserfc import jwt
from crypto_key import SymmetricKey, AsymmetricKey


class DigitalSignature:
    @classmethod
    def sign(cls, key, alg):
        header = {"alg": alg}
        claims = {"iss": "justabitcoiner"}
        token_str = jwt.encode(header, claims, key)
        print("[x] token_str:", token_str)
        return token_str

    @classmethod
    def verify(cls, value, key):
        token_obj = jwt.decode(value, key)
        header = token_obj.header
        claims = token_obj.claims
        print("[x] token_obj:", header, claims)
        return token_obj


# Symmetric
file = "secret_key.jwk"
alg = "HS256"
SymmetricKey.gen_key(file)
secret_key = SymmetricKey.get_key(file)
signed_msg = DigitalSignature.sign(secret_key, alg)
verify = DigitalSignature.verify(signed_msg, secret_key)

# Asymmetric
alg = "RS256"
AsymmetricKey.gen_key()
private_key, public_key = AsymmetricKey.get_key()
signed_msg = DigitalSignature.sign(private_key, alg)
verify = DigitalSignature.verify(signed_msg, public_key)
