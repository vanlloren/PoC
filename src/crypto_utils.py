from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib
import secrets

# Generates a Schnorr group with specified parameters
def generate_schnorr_group():
    # Generating a Schnorr group with p=3072bits, q=256bits, and g as a generator
    print("Generating Schnorr group parameters...")
    parameters = dsa.generate_parameters(key_size=3072)
    p = parameters.parameter_numbers().p
    q = parameters.parameter_numbers().q
    g = parameters.parameter_numbers().g

    return p, q, g

# Returns a SHA256 hash of the message combined with the nonce (r), truncated to 128 bits for security
# Takes as parameters a 3072-bit nonce, a message, and the group order q, and returns an integer hash value modulo q
def hash_message(nonce, message, q):
    # Encoding the nonce and message to bytes if not too long
    if nonce.bit_length() > 3072:
        raise ValueError("Nonce is too long (must be at most 3072 bits)")
    nonce_bytes = nonce.to_bytes(384, byteorder='big') #3072 bits = 384 bytes
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    elif isinstance(message, int):
        message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    elif isinstance(message, bytes):
        message_bytes = message
    else:
        raise ValueError("Unsupported message type. Must be str, int, or bytes.")
        
    # Concatenate nonce and message bytes
    combined = nonce_bytes + message_bytes
    
    # Hash the combined bytes using SHA-256
    hash_digest = hashlib.sha256(combined).digest()

    # Truncate the hash for 128-bit security
    truncated_hash = hash_digest[:16] 

    # Convert the truncated hash to an integer
    hash_int = int.from_bytes(truncated_hash, byteorder='big')
    hash_int = hash_int % q
    return hash_int

# Generates an RSA key pair for the recovery party
def generate_rsa_keypair():
    print("Generating RSA key pair for recovery party...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072  
    )
    return private_key, private_key.public_key()

# Encrypts an integer plaintext into a byte stream ciphertext
# RSA-OAEP grants IND-CPA security
# Can encrypt messages of length 256 bits
def encrypt_with_public_key(public_key, plaintext):
    # Convert the plaintext integer to bytes if representable in 256 bits
    if not isinstance(plaintext, int):
        raise ValueError("Plaintext must be an integer")
    if plaintext < 0:
        raise ValueError("Negative integers cannot be encrypted")
    if plaintext.bit_length() > 256:
        raise ValueError("Message too large for encryption (must be at most 256 bits)")
    
    
    plaintext_bytes = plaintext.to_bytes(32, byteorder='big')

    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ciphertext is returned as a stream of bytes
    return ciphertext

# Decrypts a stream of bytes
# RSA-OAEP grants IND-CPA security
# Decrypts stream of exactly 3072 bits (384 bytes)
def decrypt_with_private_key(private_key, ciphertext):
    # Decrypt the ciphertext bytes   
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return int.from_bytes(plaintext, byteorder='big')

# Generates Commitment and Decommitment for a given value
# Takes as parameter one value and the group order q, and returns a commitment and decommitment
def commit_single(value1, q):
    # Select a random nonce for the commitment
    nonce = secrets.randbelow(q)  # random nonce in the range 0 to q-1
    nonce_bytes = nonce.to_bytes(32, byteorder='big') # Convert the nonce to 256bits

    # Convert the value to 384 bytes
    value_bytes = value1.to_bytes(384, byteorder='big')

    hash_input = value_bytes + nonce_bytes
    commitment = hashlib.sha256(hash_input).digest()    

    return commitment, (value1, nonce)

# Generates Commitment and Decommitment for two values
# Takes as parameters two values and the group order q, and returns a commitment and decommitment
def commit_couple(value1, value2, q):
    # Select a random nonce for the commitment
    nonce = secrets.randbelow(q)  # random nonce in the range 0 to q-1 
    nonce_bytes = nonce.to_bytes(32, byteorder='big') # Convert the nonce to 256bits

    # Convert the values to 384 bytes each
    value1_bytes = value1.to_bytes(384, byteorder='big')
    value2_bytes = value2.to_bytes(384, byteorder='big')

    hash_input = value1_bytes + value2_bytes + nonce_bytes
    commitment = hashlib.sha256(hash_input).digest()    

    return commitment, (value1, value2, nonce)

# Verifies a commitment against a decommitment
def verify_commitment(commitment, decommitment):
    if len(decommitment) == 2:
        value1, nonce = decommitment
        value_bytes = value1.to_bytes(384, byteorder='big')
        nonce_bytes = nonce.to_bytes(32, byteorder='big')
        hash_input = value_bytes + nonce_bytes
    elif len(decommitment) == 3:
        value1, value2, nonce = decommitment
        value1_bytes = value1.to_bytes(384, byteorder='big')
        value2_bytes = value2.to_bytes(384, byteorder='big')
        nonce_bytes = nonce.to_bytes(32, byteorder='big')
        hash_input = value1_bytes + value2_bytes + nonce_bytes
    else:
        raise ValueError("Invalid decommitment format")

    expected_commitment = hashlib.sha256(hash_input).digest()
    
    if expected_commitment == commitment:
        return True
    else:        
        return False