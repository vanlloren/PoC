import pytest
import PoC_DSA.src.crypto_utils
from cryptography.hazmat.primitives.asymmetric import dsa


# Test the generation of Schnorr group parameters
def test_generate_schnorr_group():
    p, q, g = PoC_DSA.src.crypto_utils.generate_schnorr_group()
    assert p.bit_length() == 3072
    assert q.bit_length() == 256
    assert g > 1 and g < p

# Testing if p and q are prime is not necessary since the dsa.generate_parameters function guarantees
# that p and q are prime. 

# Test if g is a generator of the subgroup of order q in Z_p* (i.e., g^q mod p == 1)
def test_generator_properties():
    p, q, g = PoC_DSA.src.crypto_utils.generate_schnorr_group()
    assert pow(g, q, p) == 1

# Test if p = k*q + 1 for some integer k (i.e., p-1 is divisible by q)
def test_group_order():
    p, q, g = PoC_DSA.src.crypto_utils.generate_schnorr_group()
    assert (p - 1) % q == 0
    
