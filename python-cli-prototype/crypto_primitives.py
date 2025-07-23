import hashlib
from shamir_secret_sharing import SplitSecretSharer
try:
    import argon2
except ImportError:
    argon2 = None


# variant of secret sharing where knowing t shares does not leak the other n-t shares
# input shares should have high entropy
class NoLeakSecretSharer:
    def __init__(self, shares: list[bytes], key_threshold: int, secret_byte_len: int = 32):
        self.byte_len = secret_byte_len
        encoded_shares = [
            fast_hash(share, secret_byte_len)
            for share in shares
        ]
        self.internal_sharer = SplitSecretSharer(encoded_shares, key_threshold)
    

    def get_secret(self, known_shares: dict[int, bytes]):
        known_encoded_shares = {
            i: fast_hash(known_share, self.byte_len)
            for i, known_share in known_shares.items()
        }

        return self.internal_sharer.get_secret(known_encoded_shares)


def fast_hash(inp: bytes, byte_len=32):
    shake_object = hashlib.shake_256()
    shake_object.update(inp)

    return shake_object.digest(byte_len)


def slow_hash(inp: bytes, salt: bytes = b'fixed_salt_for_deterministic_hash', byte_len=32):
    if argon2:
        return argon2.low_level.hash_secret_raw(inp, salt,
                                                time_cost=3, memory_cost=65536, parallelism=4,
                                                hash_len=byte_len, type=argon2.low_level.Type.ID)
    else:
        print("Could not import argon2 - falling back to pbkdf2_hmac (weaker)")
        return hashlib.pbkdf2_hmac('sha256', inp, salt, 600000, dklen=byte_len)


