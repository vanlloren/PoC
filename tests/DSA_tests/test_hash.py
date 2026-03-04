import pytest
import secrets
import hashlib
from PoC_DSA.src.crypto_utils import hash_message, generate_schnorr_group

# Hash done using SHA256, truncated to 128 bits for security, and reduced modulo q
# No need to test for hash properties, just that the function behaves as expected

# Test that the real digest is the 128-bit truncated version of the full digest
def test_hash_message_truncation():
    p, q, g = generate_schnorr_group()
    
    k = secrets.randbelow(q)  # k is a random integer in the range 0 to q-1
    nonce = pow(g, k, p)  # nonce is g^k mod p
    
    message = "Test message for hash truncation"
    actual_hash = hash_message(nonce, message, q)
    
    # Compute the full hash without truncation for comparison
    nonce_bytes = nonce.to_bytes(384, byteorder='big')
    message_bytes = message.encode('utf-8')
    combined = nonce_bytes + message_bytes
    hash_digest = hashlib.sha256(combined).digest()
    
    # The expected truncated hash is the first 16 bytes of the full digest
    expected_truncated_hash = int.from_bytes(hash_digest[:16], byteorder='big') % q
    
    assert actual_hash == expected_truncated_hash

# Test that a string, an integer, and a byte message produce valid hashes
def test_hash_message():
    p, q, g = generate_schnorr_group()
    
    k = secrets.randbelow(q)  # k is a random integer in the range 0 to q-1
    nonce = pow(g, k, p)  # nonce is g^k mod p
    
    message_str = "Hello, world!"
    hash_str = hash_message(nonce, message_str, q)
    assert isinstance(hash_str, int)
    assert 0 <= hash_str < q
    
    message_int = 987654321098765432109876543210
    hash_int = hash_message(nonce, message_int, q)
    assert isinstance(hash_int, int)
    assert 0 <= hash_int < q
    
    message_bytes = b'\x00\x01\x02\x03\x04'
    hash_bytes = hash_message(nonce, message_bytes, q)
    assert isinstance(hash_bytes, int)
    assert 0 <= hash_bytes < q

# Test that a non string, non-integer, non-bytes message raises an error
def test_hash_message_invalid_type():
    p, q, g = generate_schnorr_group()
    
    k = secrets.randbelow(q)  # k is a random integer in the range 0 to q-1
    nonce = pow(g, k, p)  # nonce is g^k mod p
    
    with pytest.raises(ValueError) as excinfo:
        hash_message(nonce, 3.14, q)  # float is not a valid message type

    assert "Unsupported message type. Must be str, int, or bytes." in str(excinfo.value)

# Test with a nonce of excessive length (greater than 3072 bits)
def test_hash_message_nonce_too_long():
    p, q, g = generate_schnorr_group()
    
    # Create a nonce that is too long (e.g., 4096 bits)
    nonce = secrets.randbits(4096)  # 4096-bit nonce
    
    message = "Test message with long nonce"
    
    with pytest.raises(ValueError) as excinfo:
        hash_message(nonce, message, q)
    
    assert "Nonce is too long (must be at most 3072 bits)" in str(excinfo.value)