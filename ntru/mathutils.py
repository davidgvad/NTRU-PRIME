import math
from sympy import GF, invert
import logging
import numpy as np
from sympy.abc import x
from sympy import ZZ, Poly

# Set up logging
log = logging.getLogger("mathutils")

def is_prime(n):
    """
    Check if a number is prime.
    """
    # Test divisibility for all numbers from 2 to the square root of n
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def is_2_power(n):
    """
    Determine if a number is a power of 2.
    """
    # A number is a power of 2 if it is greater than 0 and its binary representation has exactly one '1'
    return n != 0 and (n & (n - 1) == 0)

def random_poly(length, d, neg_ones_diff=0):
    """
    Generate a random polynomial with specific numbers of 1, -1, and 0 coefficients.
    """
    # Create a polynomial with d ones, d + neg_ones_diff negative ones, and the rest zeros
    return Poly(np.random.permutation(
        np.concatenate((np.zeros(length - 2 * d - neg_ones_diff), np.ones(d), -np.ones(d + neg_ones_diff)))),
        x).set_domain(ZZ)

def invert_poly(f_poly, R_poly, p):
    """
    Attempt to find the modular inverse of a polynomial modulo another polynomial over a given field.
    """
    inv_poly = None
    # Check if p is prime and find the inverse over GF(p)
    if is_prime(p):
        log.debug("Inverting as p={} is prime".format(p))
        inv_poly = invert(f_poly, R_poly, domain=GF(p))
    elif is_2_power(p):
        # If p is a power of 2, use GF(2) and iterate the inversion
        log.debug("Inverting as p={} is 2 power".format(p))
        inv_poly = invert(f_poly, R_poly, domain=GF(2))
        e = int(math.log(p, 2))
        for i in range(1, e):
            log.debug("Inversion({}): {}".format(i, inv_poly))
            inv_poly = ((2 * inv_poly - f_poly * inv_poly ** 2) % R_poly).trunc(p)
    else:
        raise Exception("Cannot invert polynomial in Z_{}".format(p))
    log.debug("Inversion: {}".format(inv_poly))
    return inv_poly
