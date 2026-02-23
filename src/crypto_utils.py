from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib

# Returns a SHA256 hash of the message combined with the nonce, truncated to 128 bits for security
# Takes as parameters a 3072-bit nonce, a message, and the group order q, and returns an integer hash value modulo q
def hash_message(nonce, message, q):
    # Encoding the nonce and message to bytes
    nonce_bytes = nonce.to_bytes(384, byteorder='big') #3072 bits = 384 bytes
    message_bytes = message.encode('utf-8') if isinstance(message, str) else message
    
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

# Generates a Schnorr group with specified parameters
def generate_schnorr_group():
    # Generating a Schnorr group with p=3072bits, q=256bits, and g as a generator
    print("Generating Schnorr group parameters...")
    parameters = dsa.generate_parameters(key_size=3072)
    p = parameters.parameter_numbers().p
    q = parameters.parameter_numbers().q
    g = parameters.parameter_numbers().g

    print("Parameters generated:")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    return p, q, g

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
    # Convert the plaintext integer to bytes
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
# Takes as parameter one value and returns a commitment and decommitment
def commit_single(value1):
    # Select a random nonce for the commitment
    nonce = os.urandom(32)  # 256-bit random nonce

    # Convert the value to 384 bytes
    value_bytes = value1.to_bytes(384, byteorder='big')

    hash_input = value_bytes + nonce
    commitment = hashlib.sha256(hash_input).digest()    

    return commitment, (value1, nonce)

# Generates Commitment and Decommitment for two values
# Takes as parameters two values and returns a commitment and decommitment
def commit_couple(value1, value2):
    # Select a random nonce for the commitment
    nonce = os.urandom(32)  # 256-bit random nonce

    # Convert the values to 384 bytes each
    value1_bytes = value1.to_bytes(384, byteorder='big')
    value2_bytes = value2.to_bytes(384, byteorder='big')

    hash_input = value1_bytes + value2_bytes + nonce
    commitment = hashlib.sha256(hash_input).digest()    

    return commitment, (value1, value2, nonce)

# Verifies a commitment against a decommitment
def verify_commitment(commitment, decommitment):
    if len(decommitment) == 2:
        value1, nonce = decommitment
        value_bytes = value1.to_bytes(384, byteorder='big')
        hash_input = value_bytes + nonce
    elif len(decommitment) == 3:
        value1, value2, nonce = decommitment
        value1_bytes = value1.to_bytes(384, byteorder='big')
        value2_bytes = value2.to_bytes(384, byteorder='big')
        hash_input = value1_bytes + value2_bytes + nonce
    else:
        raise ValueError("Invalid decommitment format")

    expected_commitment = hashlib.sha256(hash_input).digest()
    
    if expected_commitment == commitment:
        return True
    else:        
        return False