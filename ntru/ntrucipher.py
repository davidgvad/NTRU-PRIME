from ntru.mathutils import *
import numpy as np
from sympy.abc import x
from sympy.polys.polyerrors import NotInvertible
from sympy import ZZ, Poly
import logging
from collections import Counter

# Configure logging for the module
log = logging.getLogger("ntrucipher")

class NtruCipher:
    # Class attributes initialization with None to define their existence in the class
    N = None
    p = None
    q = None
    f_poly = None
    g_poly = None
    h_poly = None
    f_p_poly = None
    f_q_poly = None
    R_poly = None

    def __init__(self, N, p, q):
        """ Initialize the NtruCipher with specified parameters N, p, and q. """
        self.N = N
        self.p = p
        self.q = q
        # Define the reduction polynomial x^N - 1 over integers
        self.R_poly = Poly(x ** N - 1, x).set_domain(ZZ)
        log.info(f"NTRU(N={N},p={p},q={q}) initiated")

    def generate_random_keys(self):
        """ Generate the public and private keys for NTRU encryption. """
        g_poly = random_poly(self.N, int(math.sqrt(self.q)))
        log.info(f"g: {g_poly}")
        log.info(f"g coeffs: {Counter(g_poly.coeffs())}")

        # Attempt to generate an invertible f_poly and corresponding public key h_poly
        tries = 10
        while tries > 0 and (self.h_poly is None):
            f_poly = random_poly(self.N, self.N // 3, neg_ones_diff=-1)
            log.info(f"f: {f_poly}")
            log.info(f"f coeffs: {Counter(f_poly.coeffs())}")
            try:
                self.generate_public_key(f_poly, g_poly)
            except NotInvertible as ex:
                log.info(f"Failed to invert f (tries left: {tries})")
                log.debug(ex)
                tries -= 1

        if self.h_poly is None:
            raise Exception("Couldn't generate invertible f")

    def generate_public_key(self, f_poly, g_poly):
        """ Generate the public key using the private key polynomials f and g. """
        self.f_poly = f_poly
        self.g_poly = g_poly
        log.debug(f"Trying to invert: {self.f_poly}")

        # Compute the inverses of f in Z_p and Z_q
        self.f_p_poly = invert_poly(self.f_poly, self.R_poly, self.p)
        self.f_q_poly = invert_poly(self.f_poly, self.R_poly, self.q)
        log.debug("f_p ok!")
        log.debug("f_q ok!")
        log.info(f"f_p: {self.f_p_poly}")
        log.info(f"f_q: {self.f_q_poly}")
        
        # Verification of inversion properties
        log.debug(f"f*f_p mod (x^n - 1): {((self.f_poly * self.f_p_poly) % self.R_poly).trunc(self.p)}")
        log.debug(f"f*f_q mod (x^n - 1): {((self.f_poly * self.f_q_poly) % self.R_poly).trunc(self.q)}")
        
        # Compute the public key h_poly
        p_f_q_poly = (self.p * self.f_q_poly).trunc(self.q)
        log.debug(f"p_f_q: {p_f_q_poly}")
        h_before_mod = (p_f_q_poly * self.g_poly).trunc(self.q)
        log.debug(f"h_before_mod: {h_before_mod}")
        self.h_poly = (h_before_mod % self.R_poly).trunc(self.q)
        log.info(f"h: {self.h_poly}")

    def encrypt(self, msg_poly, rand_poly):
        """ Encrypt a message polynomial using a random polynomial and the public key. """
        log.info(f"r: {rand_poly}")
        log.info(f"r coeffs: {Counter(rand_poly.coeffs())}")
        log.info(f"msg: {msg_poly}")
        log.info(f"h: {self.h_poly}")
        # Encrypt the message
        return (((rand_poly * self.h_poly).trunc(self.q) + msg_poly) % self.R_poly).trunc(self.q)

    def decrypt(self, msg_poly):
        """ Decrypt a message polynomial using the private key. """
        log.info(f"f: {self.f_poly}")
        log.info(f"f_p: {self.f_p_poly}")
        a_poly = ((self.f_poly * msg_poly) % self.R_poly).trunc(self.q)
        log.info(f"a: {a_poly}")
        b_poly = a_poly.trunc(self.p)
        log.info(f"b: {b_poly}")
        # Return the decrypted message
        return ((self.f_p_poly * b_poly) % self.R_poly).trunc(self.p)
