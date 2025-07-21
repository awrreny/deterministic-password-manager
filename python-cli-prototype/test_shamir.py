import pytest
from shamir_secret_sharing import SecretSharer
from random import seed, randbytes
from itertools import combinations, permutations


def test_invalid_initializations():
    with pytest.raises(ValueError):
        SecretSharer([b'\x01\x02\x03\x04'], 0)  # t must be at least 1
    with pytest.raises(ValueError):
        SecretSharer([b'\x01\x02\x03\x04'], 2)  # t must be <= n
    with pytest.raises(ValueError):
        SecretSharer([b'\x01\x02\x03\x04', b'\x05\x06', b'abcd'], 2)  # bitlength mismatch
    with pytest.raises(ValueError):
        SecretSharer([b'abc', b'def'], 1)  # invalid bitlength (not in KNOWN_POLYNOMIALS)


def test_get_secret_with_not_enough_shares():
    S = SecretSharer([b'a', b'b', b'c', b'd'], 3)
    with pytest.raises(ValueError):
        S.get_secret({0:b'a'})


def test_get_secret_with_invalid_share_index():
    S = SecretSharer([b'a', b'b', b'c', b'd'], 3)
    with pytest.raises(ValueError):
        S.get_secret({4:b'e'})
    with pytest.raises(ValueError):
        S.get_secret({-1:b'e'})


def test_get_secret_consistency_1():
    S = SecretSharer([b'a', b'b', b'c', b'd', b'e', b'f', b'h'], 3)
    assert S.get_secret({0: b'a', 1: b'b', 6: b'h'}) == S.get_secret({1: b'b', 2: b'c', 3: b'd'})


def test_get_secret_consistency_2():
    S = SecretSharer([b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x08'], 3)
    assert S.get_secret({0: b'\x01', 1: b'\x02', 2: b'\x03'}) == S.get_secret({0: b'\x01', 1: b'\x02', 6: b'\x08'})


# different order of dictionary
def test_get_secret_consistency_3():
    S = SecretSharer([b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x08'], 3)
    assert S.get_secret({0: b'\x01', 2: b'\x03', 1: b'\x02'}) == S.get_secret({0: b'\x01', 1: b'\x02', 6: b'\x08'})


# test that any valid subset gives same secret
# however dictionary still in increasing order so should also check (0, 2, 1) gives same result as (0, 1, 2)
def test_get_secret_consistency_4_all_ordered_subsets():
    t = 3
    shares = [b'\xd8', b'b', b'\xc2', b'\xe3', b'k', b'\n', b'B']
    n = len(shares)
    S = SecretSharer(shares, t)
    secret = S.get_secret({0: b'\xd8', 1: b'b', 2: b'\xc2'})
    for i in range(t, n+1):
        for comb in combinations(range(len(shares)), i):
            secret2 = S.get_secret({
                i: shares[i]
                for i in comb
            })
            assert secret == secret2


def test_get_secret_consistency_5_vary_permutations():
    t = 4
    n = 5
    seed(5)
    shares = [randbytes(1) for i in range(n)]
    S = SecretSharer(shares, t)
    secret = S.get_secret({
        i: shares[i]
        for i in range(t)
    })
    for indices in permutations(range(t), t):
        secret2 = S.get_secret({
            i: shares[i]
            for i in indices
        })
        assert secret == secret2


# test perfect secrecy by checking if, when t-1 shares are known, the secret is a bijective function of any one of the other shares
# so if the last share is uniformly distributed (unknown) then the secret is also uniformly distributed (unknown)
# (not a proof, just a test that this holds for this specific n, t, shares, etc.)
def test_perfect_secrecy():
    seed(123)
    t = 5
    n = 10
    fixed_indices = (2,4,5,6)
    varying_index = 8
    shares = [randbytes(1) for i in range(n)]
    S = SecretSharer(shares, 5)
    fixed_shares = {
        i: shares[i]
        for i in fixed_indices
    }
    seen = set()
    for last_share in range(256):
        fixed_shares[varying_index] = bytes([last_share])
        secret = S.get_secret(fixed_shares)
        assert secret not in seen
        seen.add(secret)

# TODO finish above test, commit this, add composite (byte splitting secret sharing)

