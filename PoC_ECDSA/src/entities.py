# This file contains the definitions of the entities used in the protocol such as RecoveryParty and User1 and User2.

import PoC_ECDSA.src.crypto_utils
import PoC_ECDSA.src.general_procedures
import threading
import secrets
import queue
from PoC_ECDSA.src.general_procedures import abort
import PoC_ECDSA.src.utils
import PoC_ECDSA.src.curves_utils as curves_utils

# The offline RecoveryParty
class RecoveryParty(threading.Thread):
    # Creates a recovery party with its own RSA key pair for encryption and decryption
    def __init__(self):
        super().__init__()
        self.enc_private_key, self.enc_public_key = PoC_ECDSA.src.crypto_utils.generate_rsa_keypair()
        self.running = True
        self.exceptionQueue = None
        self.party_id = 3  # The recovery party has a fixed party ID of 3
        self.signature_completed = threading.Event()

    # To set the communication queues with the users
    def set_communication_queues(self, queue1, queue2, queue3, abortExceptionQueue): 
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.abortExceptionQueue = abortExceptionQueue

    # Sets the curve parameters for the recovery party
    def set_curve_parameters(self, g, p, q):
        self.p = p
        self.q = q  # This is n of the curve, its order, but we call it q to be consistent with the DSA-like notation
        self.g = g  # This is the generating point G of the curve, but we call it g to be consistent with the DSA-like notation

    # Shares the encryption public key of the recovery party to the list of users
    def share_encryption_public_key(self, UserList):
        for user in UserList:
            user.receive_recovery_public_key(self.enc_public_key)

    def run(self):
        while self.running:
            try:
                msg = self.queue3.get(timeout=10)  # Wait for a message from the users
                self.processMessage(msg)  # Process the message and continue the protocol
            except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
                self.aborted = True
                self.running = False
                self.abortExceptionQueue.put(e)  # Put the exception in the abortExceptionQueue to communicate it to the main thread
                raise
            except queue.Empty:
                pass

    # Message processing
    def processMessage(self, msg):
        if msg.description == "wakeup" and msg.sender in [1,2]:
            self.wakeup(msg.content[0], msg.sender, msg.content[1], msg.content[2], msg.content[3])
        if msg.description == 'zk_proof_x' and msg.sender in [1,2]:
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the curve
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                # Generate c until its not 0
                while True:
                    self.c = secrets.randbelow(self.q)
                    if self.c != 0:
                        break
                if msg.sender == 1:
                    self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
                elif msg.sender == 2:
                    self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=2, content=self.c))
        if msg.description == 'zk_challenge_x' and msg.sender in [1,2]:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_3 * self.other_c % self.q
            if msg.sender == 1:
                self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
            elif msg.sender == 2:
                self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=2, content=self.z))
        if msg.description == 'zk_response_x' and msg.sender in [1,2]:
            if (msg.content % self.q) != 0  and curves_utils.scalar_mult(msg.content, self.g) == curves_utils.point_add(self.other_u, curves_utils.scalar_mult(self.c, self.other_X)):
                self.signature_1()
            else:
                PoC_ECDSA.src.general_procedures.abort()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_2_commitment" and msg.sender == 2):
            self.signature_2(msg.content)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_2_decommitment" and msg.sender == 2):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_2_commitment" and msg.sender == 2):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_2_decommitment" and msg.sender == 2):
            self.combine(msg.content)        
        if msg.description == "signature_fail" and msg.sender in [1,2]:
            self.signature_completed.set()

    # Activates the recovery signature process in P3
    def wakeup(self, message, user, A, enc_rec_1_3, enc_rec_2_3):
        # Decompose the couples of encrypted values received from the user
        self.A = A
        self.message = message
        self.curr_user = user
        enc_y_1_3, enc_y_3_1 = enc_rec_1_3
        enc_y_2_3, enc_y_3_2 = enc_rec_2_3

        # Decrypt the values using the recovery party's private key
        y_1_3 = PoC_ECDSA.src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_1_3)
        y_2_3 = PoC_ECDSA.src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_2_3)
        y_3_1 = PoC_ECDSA.src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_3_1)
        y_3_2 = PoC_ECDSA.src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_3_2)

        # Compute private share of public key
        a_3 = (2*y_3_1 - y_3_2) % self.q

        # Compute public share of public key
        A_3 = curves_utils.scalar_mult(a_3, self.g)

        # Compute private key x_3
        self.x_3 = (y_1_3 + y_2_3 + 2*y_3_2 - y_3_1) % self.q

        # TODO: Add ZKP to prove correct computation of x_3 without revealing it

        # Depending on the other party, compute omega_3
        if user == 1:
            self.omega_3 = - (self.x_3 *  pow(2, -1, self.q)) % self.q
        elif user == 2:
            self.omega_3 = - (2* self.x_3) % self.q

        # Send a message to the user to start the recovery signature protocol
        if user == 1:
            message = PoC_ECDSA.src.utils.Message(description="start_signature", sender=self.party_id, receiver=1, content=self.message)
            self.queue1.put(message)
        elif user == 2:
            message = PoC_ECDSA.src.utils.Message(description="start_signature", sender=self.party_id, receiver=2, content=self.message)
            self.queue2.put(message)

        self.zk_prove_x()
    
    def zk_prove_x(self):
        # Generate the nonce until its different than 0, 1 or q-1
        while True:
            self.zk_nonce = secrets.randbelow(self.q)
            if self.zk_nonce != 0 and self.zk_nonce != 1 and self.zk_nonce != self.q - 1:
                break
        self.u = curves_utils.scalar_mult(self.zk_nonce, self.g)
        self.X = curves_utils.scalar_mult(self.x_3, self.g)

        if self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=1, content=(self.u, self.X)))
        elif self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=2, content=(self.u, self.X)))

    # First phase of signature
    def signature_1(self):
         # Save the message to be signed
        self.msg_to_sign = self.message

        # Generate k_3
        while True:
            self.k_3 = secrets.randbelow(self.q)
            if self.k_3 != 0 and self.k_3 != 1 and self.k_3 != self.q - 1:
                break

        # Compute R_3 = g * k_3 
        self.R_3 = curves_utils.scalar_mult(self.k_3, self.g)

        # Compute the commitment for R_3
        R_3_commitment, R_3_decommitment = PoC_ECDSA.src.crypto_utils.commit_single_point(self.R_3, self.q)
        self.R_3_decommitment = R_3_decommitment

        # Send the commitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="R_3_commitment", sender=self.party_id, receiver=2, content=R_3_commitment))
        elif self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="R_3_commitment", sender=self.party_id, receiver=1, content=R_3_commitment))

    # Second phase of signature protocol
    def signature_2(self, other_R_commitment):
        self.other_R_commitment = other_R_commitment
        # Send the decommitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="R_3_decommitment", sender=self.party_id, receiver=2, content=self.R_3_decommitment))
        elif self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="R_3_decommitment", sender=self.party_id, receiver=1, content=self.R_3_decommitment))
    
    # Third phase of signature protocol
    def signature_3(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.other_R = curves_utils.generate_point(self.other_R_decommitment[0], self.other_R_decommitment[1])
            if curves_utils.is_infinity(self.other_R) or curves_utils.is_generating_point(self.other_R):
                # The protocol aborts if R_2=1 or R_2=G or R_3=1 or R_3=G, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.signature_3_part2()

    # Second part of third phase of signature protocol
    def signature_3_part2(self):
        # Compute R = R_3 + R_other 
        self.R = curves_utils.point_add(self.R_3, self.other_R)

        # If R=point at infinity, the protocol aborts, since it would cause problems in the following computations
        if curves_utils.is_infinity(self.R) or curves_utils.is_generating_point(self.R):
            PoC_ECDSA.src.general_procedures.abort()

        # Compute e = H(m || R_x) mod q
        self.e = PoC_ECDSA.src.crypto_utils.hash_message(self.R.x(), self.msg_to_sign, self.q) % self.q

        # Compute s_3 = k_3 - e * omega_3 mod q
        self.s_3 = (self.k_3 - self.e * self.omega_3) % self.q

        # Compute the commitment for s_3
        s_3_commitment, s_3_decommitment = PoC_ECDSA.src.crypto_utils.commit_single(self.s_3, self.q)
        self.s_3_decommitment = s_3_decommitment

        # Send the commitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="s_3_commitment", sender=self.party_id, receiver=2, content=s_3_commitment))
        elif self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="s_3_commitment", sender=self.party_id, receiver=1, content=s_3_commitment))

    # Fourth phase of signature protocol
    def signature_4(self, other_s_commitment):
        self.other_s_commitment = other_s_commitment
        # Send s_3 decommitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="s_3_decommitment", sender=self.party_id, receiver=2, content=self.s_3_decommitment))
        elif self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="s_3_decommitment", sender=self.party_id, receiver=1, content=self.s_3_decommitment))

    # Fifth phase of signature protocol
    def combine(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.s = (self.s_3 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = curves_utils.point_add(curves_utils.scalar_mult(self.s, self.g), curves_utils.scalar_mult(self.e, self.A))
            e_v = PoC_ECDSA.src.crypto_utils.hash_message(r_v.x(), self.msg_to_sign, self.q) % self.q
            if e_v != self.e:
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()
        
# The user1 class
class User1(threading.Thread):
    # Creates a user with a unique party ID (1) and initializes the recovery public key to None
    def __init__(self, party_id):
        super().__init__()
        self.party_id = party_id
        self.recovery_public_key = None
        self.running = True
        self.keygen_completed = threading.Event()
        self.signature_completed = threading.Event()
        self.abortExceptionQueue = None
        self.failedSignatureExceptionQueue = None
        self.recovery = False

    # Sets the communication queues with the other user and the recovery party
    def set_communication_queues(self, queue1, queue2, queue3, abortExceptionQueue, failedSignatureExceptionQueue):
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.abortExceptionQueue = abortExceptionQueue
        self.failedSignatureExceptionQueue = failedSignatureExceptionQueue

    # Receives the recovery party's encryption public key
    def receive_recovery_public_key(self, enc_public_key):
        self.recovery_public_key = enc_public_key

    # Sets the curve parameters for the user
    def set_curve_parameters(self, g, p, q):
        self.p = p
        self.q = q  # This is n of the curve, its order, but we call it q to be consistent with the DSA-like notation
        self.g = g  # This is the generating point G of the curve, but we call it g to be consistent with the DSA-like notation

    # Run the thread
    def run(self):
        while self.running:
            try:
                msg = self.queue1.get(timeout=10)  # Wait for a message from the other user or the recovery party
                self.processMessage(msg)  # Process the message and continue the protocol
            except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
                self.aborted = True
                self.running = False
                self.keygen_completed.set()
                self.abortExceptionQueue.put(e)  # Put the exception in the abortExceptionQueue to communicate it to the main thread
                raise
            except PoC_ECDSA.src.utils.SignatureException as e:
                if self.recovery:
                    self.queue3.put(PoC_ECDSA.src.utils.Message(description="signature_fail", sender=self.party_id, receiver=3, content=None))  # Inform the recovery party that the signature protocol failed
                else:
                    self.queue2.put(PoC_ECDSA.src.utils.Message(description="signature_fail", sender=self.party_id, receiver=2, content=None))  # Inform the other user that the signature protocol failed
                self.failedSignatureExceptionQueue.put((e, self.party_id))
                self.signature_completed.set()                  
                raise
            except queue.Empty:
                pass
    
    # Message processing
    def processMessage(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 2:
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the curve
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                # Generate c until its not 0
                while True:
                    self.c = secrets.randbelow(self.q)
                    if self.c != 0:
                        break
                self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=2, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 2:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_1 * self.other_c % self.q
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=2, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 2:
            if (msg.content % self.q) != 0  and curves_utils.scalar_mult(msg.content, self.g) == curves_utils.point_add(self.other_u, curves_utils.scalar_mult(self.c, self.other_X)):
                self.keygen_5_part3()
            else:
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the curve 
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                # Generate c until its not 0
                while True:
                    self.c = secrets.randbelow(self.q)
                    if self.c != 0:
                        break
                self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_1 * self.other_c % self.q
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and curves_utils.scalar_mult(msg.content, self.g) == curves_utils.point_add(self.other_u, curves_utils.scalar_mult(self.c, self.other_X)):
                self.signature_1(self.msg_content)
            else:
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 2
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.msg_content = msg.content
            self.zk_prove_x()
        if msg.description == "start_recovery_signature" and msg.sender == 0:
            self.recovery_signature_1(msg.content)
        if msg.description == "signature_fail" and msg.sender == 2:
            self.signature_completed.set()
        if msg.description == "A_Y_commitment" and msg.sender == 2:
            self.keygen_2(msg.content)
        if msg.description == "A_Y_decommitment" and msg.sender == 2:
            self.keygen_3(msg.content)
        if msg.description == "M_2" and msg.sender == 2:
            self.M_2 = msg.content
            if curves_utils.is_infinity(self.M_2) or curves_utils.is_generating_point(self.M_2):
                # The protocol aborts if M_2=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 2:
            y_2_1, rec_2_3 = msg.content
            self.y_2_1 = y_2_1
            self.rec_2_3 = rec_2_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 2:
            # Do actions
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[3]) or curves_utils.is_infinity(msg.content[4]) or curves_utils.is_infinity(msg.content[7]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[3]) or not curves_utils.validate_point(msg.content[4]) or not curves_utils.validate_point(msg.content[7]):
                PoC_ECDSA.src.general_procedures.abort()
            # check z1 and z2 != mod q
            elif (msg.content[2] % self.q == 0) or (msg.content[6] % self.q == 0):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_ECDSA.src.general_procedures.abort()
                elif curves_utils.scalar_mult(msg.content[2], self.g) != curves_utils.point_add(msg.content[0], curves_utils.scalar_mult(msg.content[1], msg.content[3])) or curves_utils.scalar_mult(msg.content[6], self.g) != curves_utils.point_add(msg.content[4], curves_utils.scalar_mult(msg.content[5], msg.content[7])):
                    PoC_ECDSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_2_commitment" and msg.sender == 2) or (msg.description == "R_3_commitment" and msg.sender == 3):
            self.signature_2(msg.content)
        if (msg.description == "R_2_decommitment" and msg.sender == 2) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_2_commitment" and msg.sender == 2) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_2_decommitment" and msg.sender == 2) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)        

    # First phase of key generation
    def keygen_1(self):
        while True:
            self.a_1 = secrets.randbelow(self.q - 1) + 1  # a_1 must be different from 0, 1 or q-1
            self.y_3_1 = secrets.randbelow(self.q - 1) + 1  # y_3_1 must be different from 0, 1 or q-1
            self.m_1 = secrets.randbelow(self.q - 1) + 1  # m_1 must be different from 0, 1 or q-1
            if self.a_1 != 0 and self.a_1 != 1 and self.a_1 != self.q - 1 and self.y_3_1 != 0 and self.y_3_1 != 1 and self.y_3_1 != self.q - 1 and self.m_1 != 0 and self.m_1 != 1 and self.m_1 != self.q - 1:
                break

        self.A_1 = curves_utils.scalar_mult(self.a_1, self.g)
        self.Y_3_1 = curves_utils.scalar_mult(self.y_3_1, self.g)

        # Compute the commitments for A_1 and Y_3_1
        A_Y_commitment, A_Y_decommitment = PoC_ECDSA.src.crypto_utils.commit_couple_point(self.A_1, self.Y_3_1, self.q)
        self.A_Y_decommitment = A_Y_decommitment

        # Send the commitment to the other user
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="A_Y_commitment", sender=self.party_id, receiver=2, content=A_Y_commitment))
        
    # Second phase of key generation
    def keygen_2(self, commitment):
        self.A_Y_other_commitment = commitment
        # Send the decommitment to the other user
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=2, content=self.A_Y_decommitment))
        
    # Third phase of key generation
    def keygen_3(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, self.A_Y_other_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_2 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_2 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_2) or curves_utils.is_generating_point(self.A_2) or curves_utils.is_infinity(self.Y_3_2) or curves_utils.is_generating_point(self.Y_3_2):
                # The protocol aborts if A_2=1 or A_2=G or Y_3_2=1 or Y_3_2=G, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    # Fourth phase of key generation
    def keygen_4(self):
        # Create polinomial f_1 = a_1 + m_1*X
        f_1 = lambda X: (self.a_1 + self.m_1 * X) % self.q  

        # Compute the shares y_1_2 = f_1(j) for j=1,2,3
        self.y_1_1 = f_1(1)
        self.y_1_2 = f_1(2)
        self.y_1_3 = f_1(3)      

        # Publish M_1 to the other user
        M_1 = curves_utils.scalar_mult(self.m_1, self.g)
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="M_1", sender=self.party_id, receiver=2, content=M_1))

        # Encrypt y_1_3 and y_3_1 with public key
        enc_y_1_3 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_1_3)
        enc_y_3_1 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_1)

        self.rec_1_3 = (enc_y_1_3, enc_y_3_1)

        # Send y_1_j and rec_1_3 to the other user
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="rec_info", sender=self.party_id, receiver=2, content=(self.y_1_2, self.rec_1_3)))
        
    # Fifth phase of key generation
    def keygen_5(self):
        self.nizkp_prove()

    def nizkp_prove(self):
        # The nonce must be different than 0, 1 or q-1
        while True:
            self.nizkp_nonce1 = secrets.randbelow(self.q)
            self.nizkp_nonce2 = secrets.randbelow(self.q)
            if self.nizkp_nonce1 != 0 and self.nizkp_nonce1 != 1 and self.nizkp_nonce1 != self.q - 1 and self.nizkp_nonce2 != 0 and self.nizkp_nonce2 != 1 and self.nizkp_nonce2 != self.q - 1:
                break        
        
        self.nizkp_u1 = curves_utils.scalar_mult(self.nizkp_nonce1, self.g)
        self.nizkp_h1 = curves_utils.scalar_mult(self.y_1_3, self.g)
        self.nizkp_c1 = PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, self.nizkp_h1, self.nizkp_u1)
        self.nizkp_z1 = (self.nizkp_nonce1 + self.y_1_3 * self.nizkp_c1) % self.q

        self.nizkp_u2 = curves_utils.scalar_mult(self.nizkp_nonce2, self.g)
        self.nizkp_h2 = curves_utils.scalar_mult(self.y_3_1, self.g)
        self.nizkp_c2 = PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, self.nizkp_h2, self.nizkp_u2)
        self.nizkp_z2 = (self.nizkp_nonce2 + self.y_3_1 * self.nizkp_c2) % self.q

        self.queue2.put(PoC_ECDSA.src.utils.Message(description="nizkp_proof", sender=self.party_id, receiver=2, content=(self.nizkp_u1, self.nizkp_c1, self.nizkp_z1, self.nizkp_h1, self.nizkp_u2, self.nizkp_c2, self.nizkp_z2, self.nizkp_h2)))

    def keygen_5_part2(self):
        if curves_utils.scalar_mult(self.y_2_1, self.g) != curves_utils.point_add(self.A_2, curves_utils.scalar_mult(self.M_2, 1)):
            PoC_ECDSA.src.general_procedures.abort()        

        # Generate x_1
        self.x_1 = (self.y_1_1 + self.y_2_1 + self.y_3_1) % self.q

        # ZKP to prove correct computation of x_i without revealing it should be added here
        self.zk_prove_x()

    def zk_prove_x(self):
        # The nonce must be different than 0, 1 or q-1
        while True:
            self.zk_nonce = secrets.randbelow(self.q)
            if self.zk_nonce != 0 and self.zk_nonce != 1 and self.zk_nonce != self.q -1:
                break

        self.u = curves_utils.scalar_mult(self.zk_nonce, self.g)
        self.X = curves_utils.scalar_mult(self.x_1, self.g)
        if self.recovery:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=1, content=(self.u, self.X)))
        else:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=2, content=(self.u, self.X)))

    def keygen_5_part3(self):
        # Compute public key A
        self.A_3 = curves_utils.point_add(curves_utils.scalar_mult(2, self.Y_3_1), curves_utils.negate_point(self.Y_3_2)) 
        self.A = curves_utils.point_add(curves_utils.point_add(self.A_1, self.A_2), self.A_3)

        # Compute omega_1
        self.omega_1 = (2 * self.x_1) % self.q

        self.keygen_completed.set()

    # First phase of signature protocol
    def signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Generate k_1
        while True:
            self.k_1 = secrets.randbelow(self.q)
            if self.k_1 != 0 and self.k_1 != 1 and self.k_1 != self.q - 1:
                break

        # Compute R_1 = g * k_1
        self.R_1 = curves_utils.scalar_mult(self.k_1, self.g)

        # Compute the commitment for R_1
        R_1_commitment, R_1_decommitment = PoC_ECDSA.src.crypto_utils.commit_single_point(self.R_1, self.q)
        self.R_1_decommitment = R_1_decommitment

        # Send the commitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="R_1_commitment", sender=self.party_id, receiver=2, content=R_1_commitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="R_1_commitment", sender=self.party_id, receiver=3, content=R_1_commitment))

    # Second phase of signature protocol
    def signature_2(self, other_R_commitment):
        self.other_R_commitment = other_R_commitment
        # Send the decommitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="R_1_decommitment", sender=self.party_id, receiver=2, content=self.R_1_decommitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="R_1_decommitment", sender=self.party_id, receiver=3, content=self.R_1_decommitment))

    # Third phase of signature protocol
    def signature_3(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.other_R = curves_utils.generate_point(self.other_R_decommitment[0], self.other_R_decommitment[1])
            if curves_utils.is_infinity(self.other_R) or curves_utils.is_generating_point(self.other_R):
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.signature_3_part2()
    
    # Second part of third phase of signature protocol
    def signature_3_part2(self):
        # Compute R = R_1 + R_other
        self.R = curves_utils.point_add(self.R_1, self.other_R)

        # If R=1 the protocol aborts, since it would cause problems in the following computations
        if curves_utils.is_infinity(self.R) or curves_utils.is_generating_point(self.R):
            PoC_ECDSA.src.general_procedures.abort()

        # Compute e = H(m || R_x) mod q
        self.e = PoC_ECDSA.src.crypto_utils.hash_message(self.R.x(), self.msg_to_sign, self.q) % self.q

        # Compute s_1 = k_1 - e * omega_1 mod q
        if self.recovery:
            self.s_1 = (self.k_1 - self.e * self.omega_1_tilde) % self.q
        else:
            self.s_1 = (self.k_1 - self.e * self.omega_1) % self.q

        # Compute the commitment for s_1
        s_1_commitment, s_1_decommitment = PoC_ECDSA.src.crypto_utils.commit_single(self.s_1, self.q)
        self.s_1_decommitment = s_1_decommitment

        # Send the commitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="s_1_commitment", sender=self.party_id, receiver=2, content=s_1_commitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="s_1_commitment", sender=self.party_id, receiver=3, content=s_1_commitment))

    # Fourth phase of signature protocol
    def signature_4(self, other_s_commitment):
        self.other_s_commitment = other_s_commitment
        # Send s_1 decommitment to the other user
        if self.curr_user == 2:
            self.queue2.put(PoC_ECDSA.src.utils.Message(description="s_1_decommitment", sender=self.party_id, receiver=2, content=self.s_1_decommitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="s_1_decommitment", sender=self.party_id, receiver=3, content=self.s_1_decommitment))

    # Fifth phase of signature protocol
    def combine(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.s = (self.s_1 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = curves_utils.point_add(curves_utils.scalar_mult(self.s, self.g), curves_utils.scalar_mult(self.e, self.A))
            e_v = PoC_ECDSA.src.crypto_utils.hash_message(r_v.x(), self.msg_to_sign, self.q) % self.q
            if e_v != self.e:
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    # First phase of recovery signature protocol
    def recovery_signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Send a message to the recovery party to wake it up and start the recovery signature protocol
        self.queue3.put(PoC_ECDSA.src.utils.Message(description="wakeup", sender=self.party_id, receiver=3, content=(self.msg_to_sign, self.A, self.rec_1_3, self.rec_2_3)))

        self.omega_1_tilde = (3 * self.omega_1) * pow(4, -1, self.q) % self.q  # omega_1_tilde = (3/4)*omega_1 mod q

        # ZKP to prove x_i computed correctly should be added here

# The user2 class
class User2(threading.Thread):
    # Creates a user with a unique party ID (2) and initializes the recovery public key to None
    def __init__(self, party_id):
        super().__init__()
        self.party_id = party_id
        self.recovery_public_key = None
        self.running = True
        self.keygen_completed = threading.Event()
        self.signature_completed = threading.Event()
        self.abortExceptionQueue = None
        self.failedSignatureExceptionQueue = None
        self.recovery = False

    def set_communication_queues(self, queue1, queue2, queue3, abortExceptionQueue, failedSignatureExceptionQueue):
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.abortExceptionQueue = abortExceptionQueue
        self.failedSignatureExceptionQueue = failedSignatureExceptionQueue

    # Receives the recovery party's encryption public key
    def receive_recovery_public_key(self, enc_public_key):
        self.recovery_public_key = enc_public_key

    # Sets the curve parameters for the user
    def set_curve_parameters(self, g, p, q):
        self.p = p
        self.q = q  # This is n of the curve, its order, but we call it q to be consistent with the DSA-like notation
        self.g = g  # This is the generating point G of the curve, but we call it g to be consistent with the DSA-like notation

    # Run the thread
    def run(self):
        while self.running:
            try:
                msg = self.queue2.get(timeout=10)  # Wait for a message from the other user or the recovery party
                self.processMessage(msg)  # Process the message and continue the protocol
            except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
                self.aborted = True
                self.running = False
                self.keygen_completed.set()
                self.abortExceptionQueue.put(e)  # Put the exception in the abortExceptionQueue to communicate it to the main thread
                raise
            except PoC_ECDSA.src.utils.SignatureException as e:
                if self.recovery:
                    self.queue3.put(PoC_ECDSA.src.utils.Message(description="signature_fail", sender=self.party_id, receiver=3, content=None))  # Inform the recovery party that the signature protocol failed
                else:
                    self.queue1.put(PoC_ECDSA.src.utils.Message(description="signature_fail", sender=self.party_id, receiver=1, content=None))  # Inform the other user that the signature protocol failed
                self.failedSignatureExceptionQueue.put((e, self.party_id))  # Put the exception and the guilty party id 
                self.signature_completed.set()
                raise
            except queue.Empty:
                pass

    # Message processing
    def processMessage(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the curve
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                # Generate c until its not 0
                while True:
                    self.c = secrets.randbelow(self.q)
                    if self.c != 0:
                        break
                self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and curves_utils.scalar_mult(msg.content, self.g) == curves_utils.point_add(self.other_u, curves_utils.scalar_mult(self.c, self.other_X)):
                self.keygen_5_part3()
            else:
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the curve
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[1]):
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                while True:
                    self.c = secrets.randbelow(self.q - 1) + 1
                    if self.c != 0:
                        break
                self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and curves_utils.scalar_mult(msg.content, self.g) == curves_utils.point_add(self.other_u, curves_utils.scalar_mult(self.c, self.other_X)):
                self.signature_1(self.msg_content)
            else:
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.msg_content = msg.content
            self.zk_prove_x()
        if msg.description == "start_recovery_signature" and msg.sender == 0:
            self.recovery_signature_1(msg.content)
        if msg.description == "signature_fail" and msg.sender == 1:
            self.signature_completed.set()
        if msg.description == "A_Y_commitment" and msg.sender == 1:
            self.keygen_2(msg.content)
        if msg.description == "A_Y_decommitment" and msg.sender == 1:
            self.keygen_3(msg.content)
        if msg.description == "M_1" and msg.sender == 1:
            self.M_1 = msg.content
            if curves_utils.is_infinity(self.M_1) or curves_utils.is_generating_point(self.M_1):
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if curves_utils.is_infinity(msg.content[0]) or curves_utils.is_infinity(msg.content[3]) or curves_utils.is_infinity(msg.content[4]) or curves_utils.is_infinity(msg.content[7]):
                PoC_ECDSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif not curves_utils.validate_point(msg.content[0]) or not curves_utils.validate_point(msg.content[3]) or not curves_utils.validate_point(msg.content[4]) or not curves_utils.validate_point(msg.content[7]):
                PoC_ECDSA.src.general_procedures.abort()
            # check z1 and z2 != mod q
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_ECDSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_ECDSA.src.general_procedures.abort()
                elif curves_utils.scalar_mult(msg.content[2], self.g) != curves_utils.point_add(msg.content[0], curves_utils.scalar_mult(msg.content[1], msg.content[3])) or curves_utils.scalar_mult(msg.content[6], self.g) != curves_utils.point_add(msg.content[4], curves_utils.scalar_mult(msg.content[5], msg.content[7])):
                    PoC_ECDSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            self.signature_2(msg.content)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)
        
    # First phase of key generation
    def keygen_1(self):  
        while True:
            self.a_2 = secrets.randbelow(self.q)  # a_2 must be different from 0, 1 and q-1
            self.y_3_2 = secrets.randbelow(self.q) # y_3_2 must be different from 0, 1 and q-1
            self.m_2 = secrets.randbelow(self.q)  # m_2 must be different from 0, 1 and q-1
            if self.a_2 != 0 and self.a_2 != 1 and self.a_2 != self.q - 1 and self.y_3_2 != 0 and self.y_3_2 != 1 and self.y_3_2 != self.q - 1 and self.m_2 != 0 and self.m_2 != 1 and self.m_2 != self.q - 1:
                break

        self.A_2 = curves_utils.scalar_mult(self.a_2, self.g)
        self.Y_3_2 = curves_utils.scalar_mult(self.y_3_2, self.g)

        # Compute the commitments for A_2 and Y_3_2
        A_Y_commitment, A_Y_decommitment = PoC_ECDSA.src.crypto_utils.commit_couple_point(self.A_2, self.Y_3_2, self.q)
        self.A_Y_decommitment = A_Y_decommitment

        # Send the commitment to the other user
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="A_Y_commitment", sender=self.party_id, receiver=1, content=A_Y_commitment))
        
    # Second phase of key generation
    def keygen_2(self, commitment):
        self.A_Y_other_commitment = commitment
        # Send the decommitment to the other user
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=1, content=self.A_Y_decommitment))

    # Third phase of key generation
    def keygen_3(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_1 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_1 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_1) or curves_utils.is_generating_point(self.A_1) or curves_utils.is_infinity(self.Y_3_1) or curves_utils.is_generating_point(self.Y_3_1):
                # The protocol aborts if A_1=1 or Y_3_1=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    # Fourth phase of key generation
    def keygen_4(self):
        # Create polinomial f_2 = a_2 + m_2*X
        f_2 = lambda X: (self.a_2 + self.m_2 * X) % self.q  

        # Compute the shares y_2_j = f_2(j) for j=1,2,3
        self.y_2_1 = f_2(1)
        self.y_2_2 = f_2(2)
        self.y_2_3 = f_2(3)      


        # Publish M_2 to the other user
        M_2 = curves_utils.scalar_mult(self.m_2, self.g)
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="M_2", sender=self.party_id, receiver=1, content=M_2))

        # Encrypt y_2_3 and y_3_2 with public key
        enc_y_2_3 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_2_3)
        enc_y_3_2 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_2)

        self.rec_2_3 = (enc_y_2_3, enc_y_3_2)

        # Send y_2_1 and rec_2_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="rec_info", sender=self.party_id, receiver=1, content=(self.y_2_1, self.rec_2_3)))
        
    # Fifth phase of key generation
    def keygen_5(self):
        self.nizkp_prove()

    def nizkp_prove(self):
        # The nonce must be different than 0, 1 and q-1
        while True:
            self.nizkp_nonce1 = secrets.randbelow(self.q)
            self.nizkp_nonce2 = secrets.randbelow(self.q)
            if self.nizkp_nonce1 != 0 and self.nizkp_nonce1 != 1 and self.nizkp_nonce1 != self.q - 1 and self.nizkp_nonce2 != 0 and self.nizkp_nonce2 != 1 and self.nizkp_nonce2 != self.q - 1:
                break

        self.nizkp_u1 = curves_utils.scalar_mult(self.nizkp_nonce1, self.g)
        self.nizkp_h1 = curves_utils.scalar_mult(self.y_2_3, self.g)
        self.nizkp_c1 = PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, self.nizkp_h1, self.nizkp_u1)
        self.nizkp_z1 = (self.nizkp_nonce1 + self.y_2_3 * self.nizkp_c1) % self.q

        self.nizkp_u2 = curves_utils.scalar_mult(self.nizkp_nonce2, self.g)
        self.nizkp_h2 = curves_utils.scalar_mult(self.y_3_2, self.g)
        self.nizkp_c2 = PoC_ECDSA.src.crypto_utils.tuple_hash(self.g, self.q, self.nizkp_h2, self.nizkp_u2)
        self.nizkp_z2 = (self.nizkp_nonce2 + self.y_3_2 * self.nizkp_c2) % self.q

        self.queue1.put(PoC_ECDSA.src.utils.Message(description="nizkp_proof", sender=self.party_id, receiver=1, content=(self.nizkp_u1, self.nizkp_c1, self.nizkp_z1, self.nizkp_h1, self.nizkp_u2, self.nizkp_c2, self.nizkp_z2, self.nizkp_h2)))

    def keygen_5_part2(self):
        if curves_utils.scalar_mult(self.y_1_2, self.g) != curves_utils.point_add(self.A_1, curves_utils.scalar_mult(self.M_1, 2)):
            PoC_ECDSA.src.general_procedures.abort()        

        # Generate x_2
        self.x_2 = (self.y_1_2 + self.y_2_2 + self.y_3_2) % self.q

        # ZKP to prove correct computation of x_2 without revealing it should be added here
        self.zk_prove_x()

    def zk_prove_x(self):
        while True:
            self.zk_nonce = secrets.randbelow(self.q)
            if self.zk_nonce != 0 and self.zk_nonce != 1 and self.zk_nonce != self.q -1:
                break
        self.u = curves_utils.scalar_mult(self.zk_nonce, self.g)
        self.X = curves_utils.scalar_mult(self.x_2, self.g)
        if self.recovery:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=1, content=(self.u, self.X)))
        else:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="zk_proof_x", sender=self.party_id, receiver=1, content=(self.u, self.X)))

    def keygen_5_part3(self):
        # Compute public key A
        self.A_3 = curves_utils.point_add(curves_utils.scalar_mult(2, self.Y_3_1), curves_utils.negate_point(self.Y_3_2))
        self.A = curves_utils.point_add(curves_utils.point_add(self.A_1, self.A_2), self.A_3)
        # Compute omega_2
        self.omega_2 = (-self.x_2) % self.q

        self.keygen_completed.set()

    # First phase of signature protocol
    def signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Generate k_2
        while True:
            self.k_2 = secrets.randbelow(self.q)
            if self.k_2 != 0 and self.k_2 != 1 and self.k_2 != self.q - 1:
                break

        # Compute R_2 = g * k_2
        self.R_2 = curves_utils.scalar_mult(self.k_2, self.g)

        # Compute the commitment for R_2
        R_2_commitment, R_2_decommitment = PoC_ECDSA.src.crypto_utils.commit_single_point(self.R_2, self.q)
        self.R_2_decommitment = R_2_decommitment

        # Send the commitment to the other user
        if self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="R_2_commitment", sender=self.party_id, receiver=1, content=R_2_commitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="R_2_commitment", sender=self.party_id, receiver=3, content=R_2_commitment))

    # Second phase of signature protocol
    def signature_2(self, other_R_commitment):
        self.other_R_commitment = other_R_commitment
        # Send the decommitment to the other user
        if self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="R_2_decommitment", sender=self.party_id, receiver=1, content=self.R_2_decommitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="R_2_decommitment", sender=self.party_id, receiver=3, content=self.R_2_decommitment))

    # Third phase of signature protocol
    def signature_3(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.other_R_commitment, other_R_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.other_R = curves_utils.generate_point(self.other_R_decommitment[0], self.other_R_decommitment[1])
            if curves_utils.is_infinity(self.other_R) or curves_utils.is_generating_point(self.other_R):
                # The protocol aborts if R_1 is the point at infinity
                PoC_ECDSA.src.general_procedures.abort()
            self.signature_3_part2()

    # Continuation of third phase of signature protocol
    def signature_3_part2(self):
        # Compute R = R_2 + R_other
        self.R = curves_utils.point_add(self.R_2, self.other_R)

        # If R is the point at infinity, the signature would be invalid, so the protocol aborts
        if curves_utils.is_infinity(self.R) or curves_utils.is_generating_point(self.R):
            PoC_ECDSA.src.general_procedures.abort()

        # Compute e = H(m || R)
        self.e = PoC_ECDSA.src.crypto_utils.hash_message(self.R.x(), self.msg_to_sign, self.q) % self.q

        # Compute s_2 = k_2 - e*omega_2 mod q
        if self.recovery:
            self.s_2 = (self.k_2 - self.e * self.omega_2_tilde) % self.q
        else:
            self.s_2 = (self.k_2 - self.e * self.omega_2) % self.q

        # Compute s_2 commitment
        s_2_commitment, s_2_decommitment = PoC_ECDSA.src.crypto_utils.commit_single(self.s_2, self.q)
        self.s_2_decommitment = s_2_decommitment

        # Send s_2 commitment to the other user
        if self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="s_2_commitment", sender=self.party_id, receiver=1, content=s_2_commitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="s_2_commitment", sender=self.party_id, receiver=3, content=s_2_commitment))

    # Fourth phase of signature protocol
    def signature_4(self, other_s_commitment):
        self.other_s_commitment = other_s_commitment
        # Send s_2 decommitment to the other user
        if self.curr_user == 1:
            self.queue1.put(PoC_ECDSA.src.utils.Message(description="s_2_decommitment", sender=self.party_id, receiver=1, content=self.s_2_decommitment))
        elif self.curr_user == 3:
            self.queue3.put(PoC_ECDSA.src.utils.Message(description="s_2_decommitment", sender=self.party_id, receiver=3, content=self.s_2_decommitment))

    # Fifth phase of signature protocol
    def combine(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.s = (self.s_2 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = curves_utils.point_add(curves_utils.scalar_mult(self.s, self.g), curves_utils.scalar_mult(self.e, self.A))
            e_v = PoC_ECDSA.src.crypto_utils.hash_message(r_v.x(), self.msg_to_sign, self.q) % self.q
            if e_v != self.e:
                PoC_ECDSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    # First phase of recovery signature protocol
    def recovery_signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Send a message to the recovery party to wake it up and start the recovery signature protocol
        self.queue3.put(PoC_ECDSA.src.utils.Message(description="wakeup", sender=self.party_id, receiver=3, content=(self.msg_to_sign, self.A, self.rec_1_3, self.rec_2_3)))

        self.omega_2_tilde = - (3 * self.omega_2)

        # ZKP to prove x_2 computed correctly should be added here