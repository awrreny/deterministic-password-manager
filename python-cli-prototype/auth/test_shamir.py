import pytest
from .shamir_secret_sharing import SecretSharer, SplitSecretSharer, split_byte_list, split_byte_dict
from crypto_primitives import NoLeakSecretSharer
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


def test_invalid_initializations_split():
    with pytest.raises(ValueError):
        SplitSecretSharer([b'a', b'ab'], 1)
    with pytest.raises(ValueError):
        SplitSecretSharer([b'ad', b'ab'], 0)
    with pytest.raises(ValueError):
        SplitSecretSharer([b'ad', b'ab'], 3)
    # no error
    SplitSecretSharer([b'abc', b'123'], 1)


def test_split_byte_list():
    inp = [b'123', b'abc']
    out = [[b'1', b'a'], [b'2', b'b'], [b'3', b'c']]
    assert split_byte_list(inp) == out


def test_split_byte_dict():
    inp = {0: b'xyz', 1: b'uvw'}
    out = [{0: b'x', 1: b'u'}, {0: b'y', 1: b'v'}, {0: b'z', 1: b'w'}]
    assert split_byte_dict(inp, 3) == out


def test_split_actually_splits():
    S = SplitSecretSharer([b'xy', b'uv'], 1)
    secret = S.get_secret({0: b'xy'})

    S1 = SecretSharer([b'x', b'u'], 1)
    secret1 = S1.get_secret({0: b'x'})

    S2 = SecretSharer([b'y', b'v'], 1)
    secret2 = S2.get_secret({1: b'v'})

    assert secret == secret1 + secret2


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


def test_get_secret_with_invalid_share_value():
    S = SecretSharer([b'a1', b'b2', b'c3', b'd4'], 1)
    with pytest.raises(ValueError):
        S.get_secret({0: b'a'})
    with pytest.raises(ValueError):
        S.get_secret({0: b'a1a'})


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
@pytest.mark.parametrize("testClass, byteLen", [(SecretSharer, 2), (SplitSecretSharer, 3), (NoLeakSecretSharer, 2)])
def test_get_secret_consistency_4_all_ordered_subsets(testClass, byteLen):
    t = 3
    n = 7
    seed(0)
    shares = [randbytes(byteLen) for i in range(7)]
    S = testClass(shares, t)
    seed(0)
    secret = S.get_secret({0: randbytes(byteLen), 1: randbytes(byteLen), 2: randbytes(byteLen)})
    for i in range(t, n+1):
        for comb in combinations(range(len(shares)), i):
            secret2 = S.get_secret({
                i: shares[i]
                for i in comb
            })
            assert secret == secret2


@pytest.mark.parametrize("testClass", [SecretSharer, SplitSecretSharer, NoLeakSecretSharer])
def test_get_secret_consistency_5_vary_permutations(testClass):
    t = 4
    n = 5
    seed(5)
    shares = [randbytes(2) for i in range(n)]
    S = testClass(shares, t)
    secret = S.get_secret({
        i: shares[i]
        for i in range(t)
    })
    # test last t points as they will have non-0 y-shift
    for indices in permutations(range(n-t, n), t):
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


def test_deterministic():
    S1 = NoLeakSecretSharer([b'a', b'b', b'c', b'd'], 3)
    S2 = NoLeakSecretSharer([b'a', b'b', b'c', b'd'], 3)

    # get secret and compare
    secret1 = S1.get_secret({0: b'a', 1: b'b', 2: b'c'})
    secret2 = S2.get_secret({0: b'a', 1: b'b', 2: b'c'})
    assert secret1 == secret2