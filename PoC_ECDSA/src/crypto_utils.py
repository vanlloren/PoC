# TODO: requires fixing the crypto utils for Elliptic Curves

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import hashlib
import secrets
import ecdsa
from ecdsa import NIST256p, ellipticcurve
from Crypto.Hash import TupleHash256 as TupleHash

# Generates an elliptic curve with specified parameters
def generate_elliptic_curve():
    curve = NIST256p  # secp256r1
    g = curve.generator     # generating point G (x, y) (the g of the DSA-like scheme)
    p = curve.curve.p()     # field prime p (the p of the DSA-like scheme)    
    n = curve.order         # generator order n (the q of the DSA-like scheme)

    return g, p, n

# Returns a SHA256 hash of the message combined with the nonce (r), truncated to 128 bits for security
# Takes as parameters a 256-bit nonce (the x-coordinate of the nonce point), a message
# and the curve order q, and returns an integer hash value modulo q
def hash_message(nonce, message, q):
    # Encoding the nonce and message to bytes if not too long
    if nonce.bit_length() > 256:
        raise ValueError("Nonce is too long (must be at most 256 bits)")
    nonce_bytes = nonce.to_bytes(32, byteorder='big') #256 bits = 32 bytes
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
# Takes as parameter one point of the elliptic curve and the curve order q
# and returns a commitment and decommitment (that contains the point coordinates and the nonce)
def commit_single_point(point, q):
    # Select a random nonce for the commitment
    nonce = secrets.randbelow(q)  # random nonce in the range 0 to q-1
    nonce_bytes = nonce.to_bytes(32, byteorder='big') # Convert the nonce to 256bits

    # Convert the value to 384 bytes
    x = point.x()
    y = point.y()
    x_bytes = x.to_bytes(32, byteorder='big') # 256 bits = 32 bytes
    y_bytes = y.to_bytes(32, byteorder='big') # 256 bits = 32 bytes
    value_bytes = x_bytes + y_bytes # Total 512 bits (64 bytes)

    hash_input = value_bytes + nonce_bytes
    commitment = hashlib.sha256(hash_input).digest()

    return commitment, (x, y, nonce)

# Generates Commitment and Decommitment for two values
# Takes as parameters two points of the elliptic curve and the curve order q
# and returns a commitment and decommitment (that contains the coordinates of both points and the nonce)
def commit_couple_point(point1, point2, q):
    # Select a random nonce for the commitment
    nonce = secrets.randbelow(q)  # random nonce in the range 0 to q-1 
    nonce_bytes = nonce.to_bytes(32, byteorder='big') # Convert the nonce to 256bits

    # Convert the values to 384 bytes each
    x1 = point1.x()
    y1 = point1.y()
    x2 = point2.x()
    y2 = point2.y()
    value1_bytes = x1.to_bytes(32, byteorder='big') + y1.to_bytes(32, byteorder='big')
    value2_bytes = x2.to_bytes(32, byteorder='big') + y2.to_bytes(32, byteorder='big')

    hash_input = value1_bytes + value2_bytes + nonce_bytes
    commitment = hashlib.sha256(hash_input).digest()    

    return commitment, (x1, y1, x2, y2, nonce)

# Verifies a commitment against a decommitment
def verify_commitment_point(commitment, decommitment):
    if len(decommitment) == 3:
        point_x, point_y, nonce = decommitment
        point_bytes = point_x.to_bytes(32, byteorder='big') + point_y.to_bytes(32, byteorder='big')
        nonce_bytes = nonce.to_bytes(32, byteorder='big')
        hash_input = point_bytes + nonce_bytes
    elif len(decommitment) == 5:
        x1, y1, x2, y2, nonce = decommitment
        value1_bytes = x1.to_bytes(32, byteorder='big') + y1.to_bytes(32, byteorder='big')
        value2_bytes = x2.to_bytes(32, byteorder='big') + y2.to_bytes(32, byteorder='big')
        nonce_bytes = nonce.to_bytes(32, byteorder='big')
        hash_input = value1_bytes + value2_bytes + nonce_bytes
    else:
        raise ValueError("Invalid decommitment format")

    expected_commitment = hashlib.sha256(hash_input).digest()
    
    if expected_commitment == commitment:
        return True
    else:        
        return False

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
        
# Used to compute the hash of the quartet g, q, h, u 
# where arg1, arg3 and arg4 are points of the curve and arg2 is the curve order n
def tuple_hash(arg1, arg2, arg3, arg4):
    # Convert arguments to bytes
    arg1_bytes = arg1.x().to_bytes(32, byteorder='big') + arg1.y().to_bytes(32, byteorder='big')  # g is 256 bits, so 64 bytes
    arg2_bytes = arg2.to_bytes(32, byteorder='big')   # q is 256 bits, so 32 bytes
    arg3_bytes = arg3.x().to_bytes(32, byteorder='big') + arg3.y().to_bytes(32, byteorder='big')  # h is 256 bits, so 64 bytes
    arg4_bytes = arg4.x().to_bytes(32, byteorder='big') + arg4.y().to_bytes(32, byteorder='big')  # u is 256 bits, so 64 bytes

    # Create a TupleHash object
    tuple_hash_obj = TupleHash.new(digest_bits=256)

    # Update the hash with the byte representations of the arguments
    tuple_hash_obj.update(arg1_bytes)
    tuple_hash_obj.update(arg2_bytes)
    tuple_hash_obj.update(arg3_bytes)
    tuple_hash_obj.update(arg4_bytes)

    # Finalize and return the hash digest as an integer
    hash_digest = tuple_hash_obj.digest()
    return int.from_bytes(hash_digest, byteorder='big')