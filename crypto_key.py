from joserfc import jwk


class SymmetricKey:
    @classmethod
    def gen_key(cls, file="secret.key", key_size=256):
        key = jwk.OctKey.generate_key(key_size)
        key = key.raw_value
        with open(file, "wb") as f:
            f.write(key)

    @classmethod
    def get_key(cls, file="secret.key"):
        with open(file, "rb") as f:
            key = f.read()
            return jwk.OctKey.import_key(key)


class AsymmetricKey:
    @classmethod
    def gen_key(cls):
        key = jwk.RSAKey.generate_key()
        private_key = key.as_pem(private=True)
        public_key = key.as_pem(private=False)
        with open("private_key.pem", "wb") as f:
            f.write(private_key)
        with open("public_key.pem", "wb") as f:
            f.write(public_key)

    @classmethod
    def get_key(cls):
        with open("private_key.pem", "rb") as f:
            private_key = f.read()
        with open("public_key.pem", "rb") as f:
            public_key = f.read()
        private_key = jwk.RSAKey.import_key(private_key)
        public_key = jwk.RSAKey.import_key(public_key)
        return (private_key, public_key)
