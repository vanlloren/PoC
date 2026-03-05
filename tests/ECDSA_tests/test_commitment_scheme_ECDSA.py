import pytest
import PoC_ECDSA.src.crypto_utils as crypto_utils
import PoC_ECDSA.src.curves_utils as curves_utils

# A hash-based commitment scheme is certainly:
# 1. Hiding: From a SHA-256 hash, it is computationally infeasible to find the original input values
# 2. Binding: Finding two different inputs with the same SHA-256 hash is computationally infeasible
# 3. Correct: The hash procedure is deterministic, so the same input will always produce the same output

# Scalar commitment has already been tested in the DSA version of this battery of tests

# Test for single point commitment scheme
def test_commitment_basic_operation():
        # Generate the curve parameters
        g, p, q, name = crypto_utils.generate_elliptic_curve()
        
        result = crypto_utils.commit_single_point(g, q)
        
        # Verifica che restituisca una tupla di 2 elementi
        assert isinstance(result, tuple)
        assert len(result) == 2
        
        commitment, decommitment = result

        assert len(commitment) == 32  # SHA-256 hash length in bytes
        
        # Verifica tipi
        assert isinstance(commitment, bytes)
        assert isinstance(decommitment, tuple)
        assert len(decommitment) == 3
        
        point_orignal_x, point_original_y, nonce = decommitment
        assert isinstance(point_orignal_x, int)
        assert isinstance(point_original_y, int)
        assert curves_utils.validate_point(curves_utils.generate_point(point_orignal_x, point_original_y)) == True
        assert isinstance(nonce, int)

# Test for couple points commitment scheme
def test_commitment_couple_basic_operation():
    g, p, q, name = crypto_utils.generate_elliptic_curve()
    
    point1 = curves_utils.scalar_mult(12345, g)
   

    result = crypto_utils.commit_couple_point(g, point1, q)

    # Verifica che restituisca una tupla di 2 elementi
    assert isinstance(result, tuple)
    assert len(result) == 2

    commitment, decommitment = result

    assert len(commitment) == 32  # SHA-256 hash length in bytes

    # Verifica tipi
    assert isinstance(commitment, bytes)
    assert isinstance(decommitment, tuple)
    assert len(decommitment) == 5
    g_original_x, g_original_y, point1_original_x, point1_original_y, nonce = decommitment
    assert isinstance(g_original_x, int)
    assert isinstance(g_original_y, int)
    assert isinstance(point1_original_x, int)
    assert isinstance(point1_original_y, int)
    assert curves_utils.validate_point(curves_utils.generate_point(g_original_x, g_original_y)) == True
    assert curves_utils.validate_point(curves_utils.generate_point(point1_original_x, point1_original_y)) == True   
    assert isinstance(nonce, int)

# Test the whole process of commitment and verification for single point and 
# couple points commitment scheme
def test_commitment_and_verification_single():
    g, p, q, name = crypto_utils.generate_elliptic_curve()
    point1 = curves_utils.scalar_mult(12345, g)
    point2 = curves_utils.scalar_mult(67890, g)

    commitment, decommitment = crypto_utils.commit_single_point(g, q)
    commitment_couple, decommitment_couple = crypto_utils.commit_couple_point(g, point1, q)
    commitment_error, decommitment_error =  crypto_utils.commit_single_point(point2, q)
    commitment_couple_error, decommitment_couple_error = crypto_utils.commit_couple_point(g, point2, q)

    assert crypto_utils.verify_commitment_point(commitment, decommitment) == True
    assert crypto_utils.verify_commitment_point(commitment_couple, decommitment_couple) == True
    assert crypto_utils.verify_commitment_point(commitment, decommitment_error) == False
    assert crypto_utils.verify_commitment_point(commitment_couple, decommitment_couple_error) == False

# No need to test for too large value that cannot be represented in 384 bytes
# In single or double commit, the value is always converted to 384 bytes, so larger values
# will be truncated.
