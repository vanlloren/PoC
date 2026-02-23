import pytest
from src.crypto_utils import commit_single, commit_couple, verify_commitment, generate_schnorr_group

# A hash-based commitment scheme is certainly:
# 1. Hiding: From a SHA-256 hash, it is computationally infeasible to find the original input values
# 2. Binding: Finding two different inputs with the same SHA-256 hash is computationally infeasible
# 3. Correct: The hash procedure is deterministic, so the same input will always produce the same output

# Test for single value commitment scheme
def test_commitment_basic_operation():
        # Generate a Schnorr group to get the group order q
        p, q, g = generate_schnorr_group()
        value = 12345
        
        result = commit_single(value, q)
        
        # Verifica che restituisca una tupla di 2 elementi
        assert isinstance(result, tuple)
        assert len(result) == 2
        
        commitment, decommitment = result

        assert len(commitment) == 32  # SHA-256 hash length in bytes
        
        # Verifica tipi
        assert isinstance(commitment, bytes)
        assert isinstance(decommitment, tuple)
        assert len(decommitment) == 2
        
        value_original, nonce = decommitment
        assert isinstance(value_original, int)
        assert isinstance(nonce, int)

# Test for couple values commitment scheme
def test_commitment_couple_basic_operation():
    p, q, g = generate_schnorr_group()
    value1 = 12345
    value2 = 67890

    result = commit_couple(value1, value2, q)

    # Verifica che restituisca una tupla di 2 elementi
    assert isinstance(result, tuple)
    assert len(result) == 2

    commitment, decommitment = result

    assert len(commitment) == 32  # SHA-256 hash length in bytes

    # Verifica tipi
    assert isinstance(commitment, bytes)
    assert isinstance(decommitment, tuple)
    assert len(decommitment) == 3
    value1_original, value2_original, nonce = decommitment
    assert isinstance(value1_original, int)
    assert isinstance(value2_original, int)
    assert isinstance(nonce, int)

# Test the whole process of commitment and verification for single value
def test_commitment_and_verification_single():
    p, q, g = generate_schnorr_group()
    value = 12345
    value2 = 67890
    value_error = 54321

    commitment, decommitment = commit_single(value, q)
    commitment_couple, decommitment_couple = commit_couple(value, value2, q)
    commitment_error, decommitment_error = commit_single(value_error, q)
    commitment_couple_error, decommitment_couple_error = commit_couple(value_error, value2, q)

    assert verify_commitment(commitment, decommitment) == True
    assert verify_commitment(commitment_couple, decommitment_couple) == True
    assert verify_commitment(commitment, decommitment_error) == False
    assert verify_commitment(commitment_couple, decommitment_couple_error) == False

# No need to test for too large value that cannot be represented in 384 bytes
# In single or double commit, the value is always converted to 384 bytes, so larger values
# will be truncated.
