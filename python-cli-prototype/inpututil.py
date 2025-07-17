def get_input(prompt, target_type = str, allowed_range = None, strip_whitespace=True):
    """
    variation of input() with type casting and validation.
        target_type: The type to which the input should be cast (e.g., int, float, str, bool)
        allowed_range: An optional range of valid values. Should be an object that supports membership testing (e.g., range, list, set)
    """
    

    if not isinstance(target_type, type):
        raise TypeError("target_type must be a type like int, str, or bool")

    # note bool("False") returns True, needs separate handling
    if target_type is bool:
        inp = get_input(prompt, str, ("true", "false", "1", "0"))
        return inp in ("true", "1")

    if allowed_range is not None and not hasattr(allowed_range, '__contains__'):
        raise TypeError("allowed_range must support membership testing (e.g., list, range). Currently: " + str(type(allowed_range)))

    while True:
        inp = input(prompt)
        if strip_whitespace:
            inp = inp.strip()
        try:
            casted_input = target_type(inp)
            if allowed_range is not None and casted_input not in allowed_range:
                print(f"Input must be within {allowed_range}")
            else:
                return casted_input
        except ValueError as e:
            print(f"Input must be of type {target_type.__name__}. Error: {e}")
    

# helper classes to use for allowed_range

# e.g get_input("Enter a non-negative integer: ", int, RANGE_INCLUSIVE(0))
class RANGE_INCLUSIVE():
    # like range() but inclusive of end, and allows None for -inf or inf
    def __init__(self, start, end=None):
        self.start = start
        self.end = end

    def __contains__(self, item):
        return (self.start is None or item >= self.start) and (self.end is None or item <= self.end)

    def __repr__(self):
        start = "-inf" if self.start is None else self.start
        end = "inf" if self.end is None else self.end
        return f"RANGE_INCLUSIVE({start}, {end})"
