from math import prod
from .galois_field import GF2n, KNOWN_POLYNOMIALS

# NO SECURITY GUARANTEE
# all cryptography here is homemade
 
# formulas taken from https://en.wikipedia.org/wiki/Lagrange_polynomial
class Interpolator:
    def __init__(self, field, xs):
        if not all([hasattr(x, 'field') and x.field is field for x in xs]):
            raise ValueError(f"x values should be in the field {field}")
        
        if xs == []:
            raise ValueError("xs list must not be empty (need at least one point to interpolate)")

        self.field = field
        self.xs = xs
        self.w = self.get_interpolation_weights(xs)
        self.degree = len(xs)-1


    # called w_j in the wikipedia article
    def get_interpolation_weights(self, xs):
        return [prod((self.field(1)/(x_j-x_m) for x_m in xs if x_j != x_m), start=self.field(1))
                for x_j in xs]


    def interpolate(self, ys):
        """
        returns a function, which when called with a single argument, evaluates the polynomial at that point
        """
        if not all([hasattr(y, 'field') and y.field is self.field for y in ys]):
            raise ValueError(f"y values should be in the field {self.field}")
        

        if len(self.xs) != len(ys):
            raise ValueError("number of x values given and y value given must match")
        

        def f(x):
            if not hasattr(x, 'field') and x.field is self.field:
                raise ValueError("can only evaluate polynomial on elements from the same field")
            
            # using the formula itself to calculate f(xi) (if xi is in self.xs) results in inf/inf
            # so this is a manual override
            for i, xi in enumerate(self.xs):
                if xi.value == x.value: return ys[i]

            numer = self.field(0)
            denom = self.field(0)
            for (xi, yi, wi) in zip(self.xs, ys, self.w):
                v = (wi/(x-xi))
                numer += v*yi
                denom += v
            return numer/denom
        
        return f


# implements secret sharing, given n fixed secrets
class SecretSharer:
    def __init__(self, shares: list[bytes], key_threshold: int):
        self.n = len(shares)
        if key_threshold > self.n or key_threshold <= 0:
            raise ValueError(f"key threshold (t = {key_threshold}) must be between 1 and key count (n = {self.n}) inclusive")
        
        self.bitlength = 8*len(shares[0])
        if not all(
            8*len(share) == self.bitlength 
            for share in shares
        ):
            raise ValueError("Each share must have the same bit length")
        
        if self.bitlength not in KNOWN_POLYNOMIALS:
            raise ValueError(f"bitlength of {self.bitlength} not supported - must be one of {'/'.join([str(x) for x in KNOWN_POLYNOMIALS.keys()])}")
        
        self.key_threshold = key_threshold
        self.field = GF2n(self.bitlength)
        self.xs = [self.field(i+1) for i in range(self.n)]
        inp_ys = [self.field(int.from_bytes(share)) for share in shares]


        self.ys_shifts = self.get_shifts(inp_ys)

    
    def get_shifts(self, inp_ys):
        # 1. interpolate polynomial from the first t shares
        I = Interpolator(self.field, self.xs[:self.key_threshold])
        poly = I.interpolate(inp_ys[:self.key_threshold])

        # 2. evaluate polynomial at all n points
        raw_ys = [
            poly(x)
            for x in self.xs
        ]

        # 3. compute shifts so one can convert from user input to the real y values (used in interpolation)
        ys_shifts = [
            raw - inp
            for (raw, inp) in zip(raw_ys, inp_ys)
        ]

        return ys_shifts


    def get_secret(self, known_shares: dict[int, bytes]):
        # known_shares is 0-indexed
        if len(known_shares) < self.key_threshold:
            raise ValueError(f"Not enough shares to reconstruct secret. (have {len(known_shares)}/{self.key_threshold} shares)")

        if not all(
            8*len(v) == self.bitlength
            for v in known_shares.values()
        ):
            raise ValueError("Bit length of shares given does not match bit length of original shares")

        if not all(
            x in range(self.n)
            for x in known_shares.keys()
        ):
            raise ValueError(f"Index of known shares should be between 0 and n-1 inclusive")

        # convert shares from bytes to field elements corresponding to inp_ys
        known_inp_ys = {
            i: self.field(int.from_bytes(share))
            for i, share in known_shares.items()
        }
        known_raw_ys = {
            i: inp_y + self.ys_shifts[i]
            for i, inp_y in known_inp_ys.items()
        }

        I = Interpolator(self.field, [self.field(i+1) for i in known_raw_ys.keys()])
        poly = I.interpolate(known_raw_ys.values())

        secret = poly(self.field(0))
        # convert back
        secret_bytes = secret.value.to_bytes(self.bitlength//8, 'big')

        return secret_bytes


def split_byte_list(byte_list: list[bytes]):
    return [[bytes([b]) for b in pair] for pair in zip(*byte_list)]


# e.g {0: b'xyz', 1: b'uvw'} -> [{0: b'x', 1: b'u'}, {0: b'y', 1: b'v'}, {0: b'z', 1: b'w'}]
def split_byte_dict(byte_dict: dict[int, bytes], byteLen):
    return [
            {
                index: bytes([known_share[i]])
                for index, known_share in byte_dict.items()
            }
            for i in range(byteLen)
        ]



class SplitSecretSharer():
    def __init__(self, shares: list[bytes], key_threshold: int):
        self.byte_length = len(shares[0])
        if not all(
            len(share) == self.byte_length 
            for share in shares
        ):
            raise ValueError("Each share must have the same bit length")
        
        split_shares = split_byte_list(shares)

        self.sharer_list = [
            SecretSharer(split_share, key_threshold) for split_share in split_shares
        ]

    
    def get_secret(self, known_shares: dict[int, bytes]):
        if not all(
            len(v) == self.byte_length
            for v in known_shares.values()
        ):
            raise ValueError("Byte length of shares given does not match byte length of original shares")

        split_known_shares = split_byte_dict(known_shares, self.byte_length)

        split_secrets = [
            S.get_secret(split_known_share)
            for S, split_known_share in zip(self.sharer_list, split_known_shares)
        ]

        secret = b''.join(split_secrets)
        return secret