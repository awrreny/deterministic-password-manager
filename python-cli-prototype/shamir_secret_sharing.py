from math import prod

 
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
class SecretCombiner:  
    pass