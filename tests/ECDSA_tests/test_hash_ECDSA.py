import pytest
import secrets
import hashlib
import PoC_ECDSA.src.crypto_utils as crypto_utils
import PoC_ECDSA.src.curves_utils as curves_utils



# Hash done using SHA256, truncated to 128 bits for security, and reduced modulo q
# No need to test for hash properties, just that the function behaves as expected

# Test that the real digest is the 128-bit truncated version of the full digest
def test_hash_message_truncation():
    # Generate the curve and save its parameters
    g, p, q, name = crypto_utils.generate_elliptic_curve()   
    
    k = secrets.randbelow(q-1) + 1  # k is a random integer in the range 1 to q-1
    nonce = curves_utils.scalar_mult(k, g)  # nonce is k*g, which is a point on the curve
    nonce_x = nonce.x()  # Get the x-coordinate of the nonce point
    
    message = "Test message for hash truncation"
    actual_hash = crypto_utils.hash_message(nonce_x, message, q)
    
    # Compute the full hash without truncation for comparison
   
    
    # Convert nonce_x to bytes (32 bytes for 256-bit numbers)
    nonce_bytes = nonce_x.to_bytes(32, byteorder='big')
    message_bytes = message.encode('utf-8')
    context_info = b"PoC_ECDSA_Schnorr_Signature"

    # H(context || len(nonce) || nonce || len(message) || message || output_length)
    combined = context_info + len(nonce_bytes).to_bytes(4, byteorder='big') + nonce_bytes + len(message_bytes).to_bytes(4, byteorder='big') + message_bytes + (16).to_bytes(4, byteorder='big')  # output_length is 16 bytes (128 bits)

    hash_digest = hashlib.shake_256(combined).digest(32)
    
    # The expected truncated hash is the first 16 bytes of the full digest
    expected_truncated_hash = int.from_bytes(hash_digest[:16], byteorder='big') % q
    
    assert actual_hash == expected_truncated_hash

# Test that a string, an integer, and a byte message produce valid hashes
def test_hash_message():
    g, p, q, name = crypto_utils.generate_elliptic_curve()

    k = secrets.randbelow(q-1) + 1  # k is a random integer in the range 1 to q-1
    nonce = curves_utils.scalar_mult(k, g)  # nonce is k*g, which is a point on the curve
    nonce_x = nonce.x()  # Get the x-coordinate of the nonce point
    nonce_bytes = nonce_x.to_bytes(32, byteorder='big')

    message_str = "Hello, world!"
    hash_str = crypto_utils.hash_message(nonce_x, message_str, q)
    assert isinstance(hash_str, int)
    assert 0 <= hash_str < q
    
    message_int = 987654321098765432109876543210
    hash_int = crypto_utils.hash_message(nonce_x, message_int, q)
    assert isinstance(hash_int, int)
    assert 0 <= hash_int < q
    
    message_bytes = b'\x00\x01\x02\x03\x04'
    hash_bytes = crypto_utils.hash_message(nonce_x, message_bytes, q)
    assert isinstance(hash_bytes, int)
    assert 0 <= hash_bytes < q

# Test that a non string, non-integer, non-bytes message raises an error
def test_hash_message_invalid_type():
    g, p, q, name = crypto_utils.generate_elliptic_curve()

    k = secrets.randbelow(q-1) + 1  # k is a random integer in the range 1 to q-1
    nonce = curves_utils.scalar_mult(k, g)  # nonce is k*g, which is a point on the curve
    nonce_x = nonce.x()  # Get the x-coordinate of the nonce point
    nonce_bytes = nonce_x.to_bytes(32, byteorder='big')

    with pytest.raises(ValueError) as excinfo:
        crypto_utils.hash_message(nonce_x, 3.14, q)  # float is not a valid message type

    assert "Unsupported message type. Must be str, int, or bytes." in str(excinfo.value)

# Tests with a nonce of excessive length (greater than 256 bits) 
def test_hash_message_nonce_excessive_length():
    g, p, q, name = crypto_utils.generate_elliptic_curve()

    # Create a nonce_x that is greater than 256 bits (e.g., 300 bits)
    nonce_x = secrets.randbits(300)  # Generate a random 300-bit integer

    message = "Test message for excessive nonce length"
    
    with pytest.raises(ValueError) as excinfo:
        crypto_utils.hash_message(nonce_x, message, q)

    assert "Nonce is too long (must be at most 256 bits)" in str(excinfo.value)
