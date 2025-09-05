# NO SECURITY GUARANTEE
# all cryptography here is homemade

# in this file, all values are polynomials with coefficients in Z_2, represented as a binary number
# where the nth least significant bit is the coefficient of x^{n-1}
# e.g 10110 = x^4 + x^2 + x^1
# 101 = x^2 + 1
# so addition = subtraction = xor
# multiplying by x^n = binary left shift n places
# dividing by x^n = binary right shift n places

def mul_no_mod(a, b):
    # polynomial multiplication without a modulus
    # same code as GF2n.mul(), with modulus removed
    r = 0
    while a != 0:
        if a & 1:
            r ^= b
        a >>= 1
        b <<= 1
    return r


def euclid_division(a, b):
    # for binary polynomials a, b, finds (q, r) s.t a = b*q + r where degree(r) < degree(b)
    # loop invariant is a = b*q + r
    if b == 0:
        raise ZeroDivisionError()
    
    r = a
    q = 0
    while True:
        # bit length is degree + 1 (if not 0)
        d = r.bit_length()-b.bit_length()
        if d < 0 or r == 0: break
        r ^= (b << d)
        q ^= (1 << d)

    assert a == mul_no_mod(b,q) ^ r
    
    return (q, r)


def extended_polynomial_gcd(a, b):
    # given binary polynomials a, b, finds (d, m, n) s.t a*m + b*n = d where d is the gcd of (a,b)

    x, y = a, b

    # m_x represents how much a there is in x
    # n_x represents how much b there is in x
    # similarly for m_y, n_y in y
    # i.e m and n satisfy m_x*a + n_x*b = x
    # m2 and n2 satisfy m_y*a + n_y*b = y
    (m_x, m_y) = 1, 0
    (n_x, n_y) = 0, 1
 
    while y != 0:
        q, r = euclid_division(x, y)
        x, y = y, r
        # using the fact that r = x - y*q
        m_x, m_y = m_y, m_x ^ mul_no_mod(m_y, q)
        n_x, n_y = n_y, n_x ^ mul_no_mod(n_y, q)
    
    return (x, m_x, n_x)



"""
sage: GF(2)['x'].irreducible_element(8)
x^8 + x^4 + x^3 + x^2 + 1
sage: GF(2)['x'].irreducible_element(16)
x^16 + x^5 + x^3 + x^2 + 1
sage: GF(2)['x'].irreducible_element(32)
x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1
sage: GF(2)['x'].irreducible_element(64)
x^64 + x^33 + x^30 + x^26 + x^25 + x^24 + x^23 + x^22 + x^21 + x^20 + x^18 + x^13 + x^12 + x^11 + x^10 + x^7 + x^5 + x^4 + x^2 + x + 1
sage: GF(2)['x'].irreducible_element(128)
x^128 + x^7 + x^2 + x + 1
sage: GF(2)['x'].irreducible_element(256)
x^256 + x^10 + x^5 + x^2 + 1
"""
# known irreducible polynomials for various bit lengths
KNOWN_POLYNOMIALS = {
    8: 1 << 8 | 1 << 4 | 1 << 3 | 1 << 2 | 1,  # x^8 + x^4 + x^3 + x^2 + 1
    16: 1 << 16 | 1 << 5 | 1 << 3 | 1 << 2 | 1,  # x^16 + x^5 + x^3 + x^2 + 1
    32: 1 << 32 | 1 << 15 | 1 << 9 | 1 << 7 | 1 << 4 | 1 << 3 | 1,  # x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + 1
    64: 1 << 64 | 1 << 33 | 1 << 30 | 1 << 26 | 1 << 25 | 1 << 24 | 1 << 23 | 1 << 22 | 1 << 21 | 1 << 20 |
      1 << 18 | 1 << 13 | 1 << 12 | 1 << 11 | 1 << 10 | 1 << 7 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1,  
      # x^64 + x^33 + x^30 + x^26 + x^25 + x^24 + x^23 + x^22 + x^21 + x^20 + x^18 + x^13 + x^12 + x^11 + x^10 + x^7 + x^5 + x^4 + x^2 + x + 1
    128: 1 << 128 | 1 << 7 | 1 << 2 | 1 << 1 | 1,  # x^128 + x^7 + x^2 + x + 1
    256: 1 << 256 | 1 << 10 | 1 << 5 | 1 << 2 | 1,  # x^256 + x^10 + x^5 + x^2 + 1
}



# class for GF(2^n)
class GF2n:
    def __init__(self, bitlength):
        self.bitlength = bitlength
        if bitlength not in KNOWN_POLYNOMIALS:
            raise ValueError(f"Unsupported bit length: {bitlength}. Supported lengths are: {list(KNOWN_POLYNOMIALS.keys())}")

        self.modulus = KNOWN_POLYNOMIALS[bitlength]

    def add(self, a, b):
        return a^b
    
    def mul(self, a, b):
        # polynomial multiplication in GF(2^n)

        # proof of correctness:
        # loop invariant a*b - r constant
        # each loop, a is either of the form kx or kx+1 where k is some polynomial
        # if a=kx, then (kx,b,r) -> (k,bx,r) preserves loop invariant
        # if a=kx+1, then (kx+1,b,r) -> (k,bx,r+b) preserves loop invariant
        # adding modulus does not affect value in GF(2^n)

        # precondition r = 0
        r = 0
        while a != 0:
            if a & 1:
                r ^= b
            a >>= 1
            b <<= 1
            if (b >> self.bitlength):
                b ^= self.modulus
        return r
        # postcondition a=0
        # taking a*b-r=c, before the loop c=a*b and after the loop c=r thus a*b=r after the loop
        # guaranteed to terminate as a decreases each iteration
        

    def inverse(self, a):
        if a == 0:
            raise ZeroDivisionError("0 does not have a multiplicative inverse")
        gcd, i, _ = extended_polynomial_gcd(a, self.modulus)
        # a*i + _*p = 1
        # so a*i === 1 (mod p)
        assert gcd == 1
        assert self.mul(a,i) == 1
        return i


    def div(self, a, b):
        return self.mul(a, self.inverse(b))

    
    def __call__(self, value):
        if not isinstance(value, int):
            raise TypeError("Value must be an integer")
        if isinstance(value, int):
            if value.bit_length() > self.bitlength:
                raise ValueError("Value is too large to be in field")
            # # note self.modulus.bit_length() = self.bitlength + 1
            # while value.bit_length() > self.bitlength:
            #     # reduce value by the modulus polynomial
            #     value ^= self.modulus << (value.bit_length() - self.bitlength - 1)
            
            return field_element(value, self)

class field_element:
    def __init__(self, value, field):
        if not isinstance(value, int):
            raise TypeError("Value must be an integer")
        self.value = value
        self.field = field

    def __add__(self, other):
        if not isinstance(other, field_element) or self.field is not other.field:
            raise TypeError("Can only add elements of the same field")
        return self.field(self.field.add(self.value, other.value))

    def __sub__(self, other):
        return self + other

    def __mul__(self, other):
        if not isinstance(other, field_element) or self.field is not other.field:
            raise TypeError("Can only multiply elements of the same field")
        
        return self.field(self.field.mul(self.value, other.value))
    
    def __truediv__(self, other):
        if not isinstance(other, field_element) or self.field is not other.field:
            raise TypeError("Can only divide elements of the same field")
        
        return self.field(self.field.div(self.value, other.value))
    

    # to make 1/x work
    def __rtruediv__(self, other):
        if other == 1:
            return self.field(self.field.inverse(self.value))
        
        raise TypeError("Can only divide field elements by each other, or 1 by a field element")


            
        
    def __repr__(self):
        # return binary representation of the value, padded to the bitlength
        return f"{self.value:0{self.field.bitlength}b}"
    

