import hashlib
try:
    import argon2
except ImportError:
    argon2 = None


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


