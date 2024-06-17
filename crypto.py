from joserfc import jwe
from crypto_key import SymmetricKey, AsymmetricKey


class Cryptography:
    @classmethod
    def encrypt(cls, key, alg):
        protected = {"alg": alg, "enc": "A128GCM"}
        encrypted_data = jwe.encrypt_compact(protected, "hello, world", key)
        print("[x] encrypted_data:", encrypted_data)
        return encrypted_data

    @classmethod
    def decrypt(cls, value, key):
        obj = jwe.decrypt_compact(value, key)
        decrypted_data = obj.plaintext.decode()
        print("[x] decrypted data:", decrypted_data)


# Symmetric
file = "secret_key.jwk"
alg = "A128KW"
SymmetricKey.gen_key(file, 128)
secret_key = SymmetricKey.get_key(file)
data = Cryptography.encrypt(secret_key, alg)
data = Cryptography.decrypt(data, secret_key)

# Asymmetric
alg = "RSA-OAEP"
AsymmetricKey.gen_key()
private_key, public_key = AsymmetricKey.get_key()
data = Cryptography.encrypt(public_key, alg)
data = Cryptography.decrypt(data, private_key)
