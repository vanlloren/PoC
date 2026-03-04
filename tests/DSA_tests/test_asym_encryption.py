import pytest
import PoC_DSA.src.crypto_utils
from cryptography.hazmat.primitives.asymmetric import rsa

# Test the 3-step procedure of generation, encryption and decryption using RSA keys
def test_rsa_encryption_decryption():
    # Generate RSA key pair
    private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()

    # Define a plaintext integer (e.g., a hash value)
    plaintext = 12345678901234567890123456789012345678

    # Encrypt the plaintext using the public key
    ciphertext = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, plaintext)

    # Decrypt the ciphertext using the private key
    decrypted = PoC_DSA.src.crypto_utils.decrypt_with_private_key(private_key, ciphertext)

    # Assert that the decrypted plaintext matches the original plaintext
    assert decrypted == plaintext

def test_max_256bit_message():
        private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()        
        
        max_256bit = (1 << 256) - 1  # Maximum 256-bit integer
        
        ciphertext = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, max_256bit)
        decrypted = PoC_DSA.src.crypto_utils.decrypt_with_private_key(private_key, ciphertext)
        
        assert decrypted == max_256bit

def test_min_256bit_message():
        private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
        
        min_message = 0
        
        ciphertext = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, min_message)
        decrypted = PoC_DSA.src.crypto_utils.decrypt_with_private_key(private_key, ciphertext)
        
        assert decrypted == min_message

# Test that encrypting a message larger than 256 bits raises an error 
def test_encrypt_large_message():
    private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    
    large_message = (1 << 256)  # 257 bits
    
    with pytest.raises(ValueError) as exc_info:
        PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, large_message)
    
    assert "Message too large for encryption (must be at most 256 bits)" in str(exc_info.value)

# Test that encrypting a negative integer raises an error 
def test_encrypt_negative_message():
    private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    
    negative_message = -1
    
    with pytest.raises(ValueError) as exc_info:
        PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, negative_message)
    
    assert "Negative integers cannot be encrypted" in str(exc_info.value)

# Test that encrypting a non-integer raises an error
def test_encrypt_non_integer():
    private_key, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    
    non_integer_message = "This is a string, not an integer."
    
    with pytest.raises(ValueError) as exc_info:
        PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, non_integer_message)

    assert "Plaintext must be an integer" in str(exc_info.value)

# Test that decrypting with wrong private key generates an error
def test_decrypt_with_wrong_key():
    # Generate two different RSA key pairs
    private_key1, public_key1 = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    private_key2, public_key2 = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    
    plaintext = 12345678901234567890123456789012345678
    
    # Encrypt with the first public key
    ciphertext = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key1, plaintext)
    
    # Decrypt with the second private key (should not match original plaintext)
    with pytest.raises(ValueError) as exc_info:
        PoC_DSA.src.crypto_utils.decrypt_with_private_key(private_key2, ciphertext)
    
    assert "Decryption failed" in str(exc_info.value)

# IND-CPA compliancy test battery:
# 1. Non-determinism
def test_encryption_non_deterministic():
    _, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    message = 42424242
    
    cipher1 = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, message)
    cipher2 = PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, message)
    
    # Devono essere diversi grazie a OAEP
    assert cipher1 != cipher2

# 2. Uniformity of ciphertexts (i.e., ciphertexts should look random)
def test_ciphertext_uniformity():
    _, public_key = PoC_DSA.src.crypto_utils.generate_rsa_keypair()
    message = 42424242
    
    ciphertexts = [PoC_DSA.src.crypto_utils.encrypt_with_public_key(public_key, message) for _ in range(100)]
    
    # Check that the ciphertexts are not all the same and appear random
    assert len(set(ciphertexts)) > 1

