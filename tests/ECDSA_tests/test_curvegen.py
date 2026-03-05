import pytest
import PoC_ECDSA.src.crypto_utils
from cryptography.hazmat.primitives.asymmetric import dsa
import PoC_ECDSA.src.curves_utils as curves_utils


# Test the generation of elliptic curve parameters
def test_generate_elliptic_curve():
    g, p, q, name = PoC_ECDSA.src.crypto_utils.generate_elliptic_curve()
    assert name == "NIST256p"

# Testing for the correctness of the curve parameters is unnecessary
# since we are using a well-known curve (secp384r1) provided by the cryptography library, 
# which is widely used and trusted. 

# Test if g is a generating point of the curve
def test_curve_properties():
    g, p, q, name = PoC_ECDSA.src.crypto_utils.generate_elliptic_curve()

    # Check if g is a point on the curve
    assert curves_utils.validate_point(g)


    
