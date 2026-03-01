# This file contains the definitions of the entities used in the protocol such as RecoveryParty and User1 and User2.

import src.crypto_utils
import src.general_procedures
import threading
import secrets
import queue
from src.general_procedures import abort

# The offline RecoveryParty
class RecoveryParty(threading.Thread):
    # Creates a recovery party with its own RSA key pair for encryption and decryption
    def __init__(self):
        super().__init__()
        self.enc_private_key, self.enc_public_key = src.crypto_utils.generate_rsa_keypair()
        self.running = True
        self.exceptionQueue = None
        self.party_id = 3  # The recovery party has a fixed party ID of 3

    # To set the communication queues with the users
    def set_communication_queues(self, queue1, queue2, queue3, exceptionQueue): 
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.exceptionQueue = exceptionQueue

    # Sets the group parameters for the recovery party
    def set_group_parameters(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

    # Shares the encryption public key of the recovery party to the list of users
    def share_encryption_public_key(self, UserList):
        for user in UserList:
            user.receive_recovery_public_key(self.enc_public_key)

    def run(self):
        while self.running:
            try:
                msg = self.queue3.get(timeout=10)  # Wait for a message from the users
            except queue.Empty:
                pass
        

    # Activates the recovery signature process in P3
    def wakeup(self, message, user, enc_rec_1_3, enc_rec_2_3):
        # Decompose the couples of encrypted values received from the user
        enc_y_1_3, enc_y_3_1 = enc_rec_1_3
        enc_y_2_3, enc_y_3_2 = enc_rec_2_3

        # Decrypt the values using the recovery party's private key
        y_1_3 = src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_1_3)
        y_2_3 = src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_2_3)
        y_3_1 = src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_3_1)
        y_3_2 = src.crypto_utils.decrypt_with_private_key(self.enc_private_key, enc_y_3_2)

        # Compute private share of public key
        a_3 = (2*y_3_1 - y_3_2) % self.q

        # Compute public share of public key
        A_3 = pow(self.g, a_3, self.p)

        # Compute private key x_3
        x_3 = (y_1_3 + y_2_3 + 2*y_3_2 - y_3_1) % self.q

        # TODO: Add ZKP to prove correct computation of x_3 without revealing it

        # Depending on the other party, compute omega_3
        if user.party_id == 1:
            self.omega_3 = - (x_3 // 2) % self.q
        elif user.party_id == 2:
            self.omega_3 = - (2* x_3) % self.q
        
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

    # Sets the group parameters for the user
    def set_group_parameters(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

    # Run the thread
    def run(self):
        while self.running:
            try:
                msg = self.queue1.get(timeout=10)  # Wait for a message from the other user or the recovery party
                self.processMessage(msg)  # Process the message and continue the protocol
            except src.utils.ProtocolAbortedException as e:
                self.aborted = True
                self.running = False
                self.keygen_completed.set()
                self.abortExceptionQueue.put(e)  # Put the exception in the abortExceptionQueue to communicate it to the main thread
                raise
            except src.utils.SignatureException as e:
                self.queue2.put(src.utils.Message(description="signature_fail", sender=self.party_id, receiver=2, content=None))  # Inform the other user that the signature protocol failed
                self.failedSignatureExceptionQueue.put((e, self.party_id))
                self.signature_completed.set()                  
                raise
            except queue.Empty:
                pass
    
    # Message processing
    def processMessage(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.signature_1(msg.content)
        if msg.description == "signature_fail" and msg.sender == 2:
            self.signature_completed.set()
        if msg.description == "A_Y_commitment" and msg.sender == 2:
            self.keygen_2(msg.content)
        if msg.description == "A_Y_decommitment" and msg.sender == 2:
            self.keygen_3(msg.content)
        if msg.description == "M_2" and msg.sender == 2:
            self.M_2 = msg.content
            if self.M_2 == 1:
                # The protocol aborts if M_2=1, since it would cause problems in the following computations
                src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 2:
            y_2_1, rec_2_3 = msg.content
            self.y_2_1 = y_2_1
            self.rec_2_3 = rec_2_3
            self.keygen_5()
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
        self.a_1 = secrets.randbelow(self.q - 1) + 1  # a_1 must be different from 0 to avoid A_1=1
        self.y_3_1 = secrets.randbelow(self.q - 1) + 1  # y_3_1 must be different from 0 to avoid Y_3_1=1
        self.m_1 = secrets.randbelow(self.q - 1) + 1  # m_1 must be different from 0 to avoid M_1=1

        self.A_1 = pow(self.g, self.a_1, self.p)
        self.Y_3_1 = pow(self.g, self.y_3_1, self.p)

        # Compute the commitments for A_1 and Y_3_1
        A_Y_commitment, A_Y_decommitment = src.crypto_utils.commit_couple(self.A_1, self.Y_3_1, self.q)
        self.A_Y_decommitment = A_Y_decommitment

        # Send the commitment to the other user
        self.queue2.put(src.utils.Message(description="A_Y_commitment", sender=self.party_id, receiver=2, content=A_Y_commitment))
        
    # Second phase of key generation
    def keygen_2(self, commitment):
        self.A_Y_other_commitment = commitment
        # Send the decommitment to the other user
        self.queue2.put(src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=2, content=self.A_Y_decommitment))
        
    # Third phase of key generation
    def keygen_3(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.A_Y_other_commitment, self.A_Y_other_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            if self.A_Y_other_decommitment[0] == 1 or self.A_Y_other_decommitment[1] == 1:
                # The protocol aborts if A_2=1 or Y_3_2=1, since it would cause problems in the following computations
                src.general_procedures.abort()
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
        M_1 = pow(self.g, self.m_1, self.p)
        self.queue2.put(src.utils.Message(description="M_1", sender=self.party_id, receiver=2, content=M_1))

        # Encrypt y_1_3 and y_3_1 with public key
        enc_y_1_3 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_1_3)
        enc_y_3_1 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_1)

        self.rec_1_3 = (enc_y_1_3, enc_y_3_1)

        # Send y_1_j and rec_1_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue2.put(src.utils.Message(description="rec_info", sender=self.party_id, receiver=2, content=(self.y_1_2, self.rec_1_3)))
        
    # Fifth phase of key generation
    def keygen_5(self):
        # MISSING TODO: Check NIZKP

        if pow(self.g, self.y_2_1, self.p) != self.A_Y_other_decommitment[0] * pow(self.M_2, 1, self.p) % self.p:
            src.general_procedures.abort()        

        # Generate x_1
        self.x_1 = (self.y_1_1 + self.y_2_1 + self.y_3_1) % self.q

        # ZKP to prove correct computation of x_i without revealing it should be added here
        # TODO: Add ZKP

        # Compute public key A
        self.A_3 = pow(self.Y_3_1, 2, self.p) * pow(self.A_Y_other_decommitment[1], -1, self.p) % self.p
        self.A = (self.A_1 * self.A_Y_other_decommitment[0] * self.A_3) % self.p

        # Compute omega_1
        self.omega_1 = (2 * self.x_1) % self.q

        self.keygen_completed.set()

    # First phase of signature protocol
    def signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Generate k_1
        self.k_1 = secrets.randbelow(self.q - 1) + 1

        # Compute R_1 = g^k_1 mod p
        self.R_1 = pow(self.g, self.k_1, self.p)

        # Compute the commitment for R_1
        R_1_commitment, R_1_decommitment = src.crypto_utils.commit_single(self.R_1, self.q)
        self.R_1_decommitment = R_1_decommitment

        # Send the commitment to the other user
        self.queue2.put(src.utils.Message(description="R_1_commitment", sender=self.party_id, receiver=2, content=R_1_commitment))

    # Second phase of signature protocol
    def signature_2(self, other_R_commitment):
        self.other_R_commitment = other_R_commitment
        # Send the decommitment to the other user
        self.queue2.put(src.utils.Message(description="R_1_decommitment", sender=self.party_id, receiver=2, content=self.R_1_decommitment))

    # Third phase of signature protocol
    def signature_3(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                src.general_procedures.abort()
            self.signature_3_part2()
    
    # Second part of third phase of signature protocol
    def signature_3_part2(self):
        # Compute R = R_1 * R_other mod p
        self.R = (self.R_1 * self.other_R_decommitment[0]) % self.p

        # If R=1 the protocol aborts, since it would cause problems in the following computations
        if self.R == 1:
            src.general_procedures.abort()

        # Compute e = H(m || R) mod q
        self.e = src.crypto_utils.hash_message(self.R, self.msg_to_sign, self.q) % self.q

        # Compute s_1 = k_1 - e * omega_1 mod q
        self.s_1 = (self.k_1 - self.e * self.omega_1) % self.q

        # Compute the commitment for s_1
        s_1_commitment, s_1_decommitment = src.crypto_utils.commit_single(self.s_1, self.q)
        self.s_1_decommitment = s_1_decommitment

        # Send the commitment to the other user
        self.queue2.put(src.utils.Message(description="s_1_commitment", sender=self.party_id, receiver=2, content=s_1_commitment))

    # Fourth phase of signature protocol
    def signature_4(self, other_s_commitment):
        self.other_s_commitment = other_s_commitment
        # Send s_1 decommitment to the other user
        self.queue2.put(src.utils.Message(description="s_1_decommitment", sender=self.party_id, receiver=2, content=self.s_1_decommitment))

    # Fifth phase of signature protocol
    def combine(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.s = (self.s_1 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q
            if e_v != self.e:
                src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

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

    def set_communication_queues(self, queue1, queue2, queue3, abortExceptionQueue, failedSignatureExceptionQueue):
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.abortExceptionQueue = abortExceptionQueue
        self.failedSignatureExceptionQueue = failedSignatureExceptionQueue

    # Receives the recovery party's encryption public key
    def receive_recovery_public_key(self, enc_public_key):
        self.recovery_public_key = enc_public_key

    # Sets the group parameters for the user
    def set_group_parameters(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

    # Run the thread
    def run(self):
        while self.running:
            try:
                msg = self.queue2.get(timeout=10)  # Wait for a message from the other user or the recovery party
                self.processMessage(msg)  # Process the message and continue the protocol
            except src.utils.ProtocolAbortedException as e:
                self.aborted = True
                self.running = False
                self.keygen_completed.set()
                self.abortExceptionQueue.put(e)  # Put the exception in the abortExceptionQueue to communicate it to the main thread
                raise
            except src.utils.SignatureException as e:
                self.queue1.put(src.utils.Message(description="signature_fail", sender=self.party_id, receiver=1, content=None))  # Inform the other user that the signature protocol failed
                self.failedSignatureExceptionQueue.put((e, self.party_id))  # Put the exception and the guilty party id 
                self.signature_completed.set()
                raise
            except queue.Empty:
                pass

    # Message processing
    def processMessage(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.signature_1(msg.content)
        if msg.description == "signature_fail" and msg.sender == 1:
            self.signature_completed.set()
        if msg.description == "A_Y_commitment" and msg.sender == 1:
            self.keygen_2(msg.content)
        if msg.description == "A_Y_decommitment" and msg.sender == 1:
            self.keygen_3(msg.content)
        if msg.description == "M_1" and msg.sender == 1:
            self.M_1 = msg.content
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
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
        self.a_2 = secrets.randbelow(self.q - 1) + 1  # a_2 must be different from 0 to avoid A_2=1
        self.y_3_2 = secrets.randbelow(self.q - 1) + 1 # y_3_2 must be different from 0 to avoid Y_3_2=1
        self.m_2 = secrets.randbelow(self.q - 1) + 1  # m_2 must be different from 0 to avoid M_2=1

        self.A_2 = pow(self.g, self.a_2, self.p)
        self.Y_3_2 = pow(self.g, self.y_3_2, self.p)

        # Compute the commitments for A_2 and Y_3_2
        A_Y_commitment, A_Y_decommitment = src.crypto_utils.commit_couple(self.A_2, self.Y_3_2, self.q)
        self.A_Y_decommitment = A_Y_decommitment

        # Send the commitment to the other user
        self.queue1.put(src.utils.Message(description="A_Y_commitment", sender=self.party_id, receiver=1, content=A_Y_commitment))
        
    # Second phase of key generation
    def keygen_2(self, commitment):
        self.A_Y_other_commitment = commitment
        # Send the decommitment to the other user
        self.queue1.put(src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=1, content=self.A_Y_decommitment))

    # Third phase of key generation
    def keygen_3(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            if self.A_Y_other_decommitment[0] == 1 or self.A_Y_other_decommitment[1] == 1:
                # The protocol aborts if A_1=1 or Y_3_1=1, since it would cause problems in the following computations
                src.general_procedures.abort()
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
        M_2 = pow(self.g, self.m_2, self.p)
        self.queue1.put(src.utils.Message(description="M_2", sender=self.party_id, receiver=1, content=M_2))

        # Encrypt y_2_3 and y_3_2 with public key
        enc_y_2_3 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_2_3)
        enc_y_3_2 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_2)

        self.rec_2_3 = (enc_y_2_3, enc_y_3_2)

        # Send y_2_1 and rec_2_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue1.put(src.utils.Message(description="rec_info", sender=self.party_id, receiver=1, content=(self.y_2_1, self.rec_2_3)))
        
    # Fifth phase of key generation
    def keygen_5(self):
        # MISSING TODO: Check NIZKP

        if pow(self.g, self.y_1_2, self.p) != self.A_Y_other_decommitment[0] * pow(self.M_1, 2, self.p) % self.p:
            src.general_procedures.abort()        

        # Generate x_2
        self.x_2 = (self.y_1_2 + self.y_2_2 + self.y_3_2) % self.q

        # ZKP to prove correct computation of x_2 without revealing it should be added here
        # TODO: Add ZKP

        # Compute public key A
        self.A_3 = pow(self.A_Y_other_decommitment[1], 2, self.p) * pow(self.Y_3_2, -1, self.p) % self.p
        self.A = (self.A_2 * self.A_Y_other_decommitment[0] * self.A_3) % self.p

        # Compute omega_2
        self.omega_2 = (-self.x_2) % self.q

        self.keygen_completed.set()

    # First phase of signature protocol
    def signature_1(self, msg):
        # Save the message to be signed
        self.msg_to_sign = msg

        # Generate k_2
        self.k_2 = secrets.randbelow(self.q - 1) + 1

        # Compute R_2 = g^k_2 mod p
        self.R_2 = pow(self.g, self.k_2, self.p)

        # Compute the commitment for R_2
        R_2_commitment, R_2_decommitment = src.crypto_utils.commit_single(self.R_2, self.q)
        self.R_2_decommitment = R_2_decommitment

        # Send the commitment to the other user
        self.queue1.put(src.utils.Message(description="R_2_commitment", sender=self.party_id, receiver=1, content=R_2_commitment))

    # Second phase of signature protocol
    def signature_2(self, other_R_commitment):
        self.other_R_commitment = other_R_commitment
        # Send the decommitment to the other user
        self.queue1.put(src.utils.Message(description="R_2_decommitment", sender=self.party_id, receiver=1, content=self.R_2_decommitment))

    # Third phase of signature protocol
    def signature_3(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_R_commitment, other_R_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_1=1, since it would cause problems in the following computations
                src.general_procedures.abort()
            self.signature_3_part2()

    # Continuation of third phase of signature protocol
    def signature_3_part2(self):
        # Compute R = R_2* R_other mod p
        self.R = (self.other_R_decommitment[0] * self.R_2) % self.p

        # If R=1, the signature would be invalid, so the protocol aborts
        if self.R == 1:
            src.general_procedures.abort()

        # Compute e = H(m || R)
        self.e = src.crypto_utils.hash_message(self.R, self.msg_to_sign, self.q) % self.q

        # Compute s_2 = k_2 - e*omega_2 mod q
        self.s_2 = (self.k_2 - self.e * self.omega_2) % self.q

        # Compute s_2 commitment
        s_2_commitment, s_2_decommitment = src.crypto_utils.commit_single(self.s_2, self.q)
        self.s_2_decommitment = s_2_decommitment

        # Send s_2 commitment to the other user
        self.queue1.put(src.utils.Message(description="s_2_commitment", sender=self.party_id, receiver=1, content=s_2_commitment))

    # Fourth phase of signature protocol
    def signature_4(self, other_s_commitment):
        self.other_s_commitment = other_s_commitment
        # Send s_2 decommitment to the other user
        self.queue1.put(src.utils.Message(description="s_2_decommitment", sender=self.party_id, receiver=1, content=self.s_2_decommitment))

    # Fifth phase of signature protocol
    def combine(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.s = (self.s_2 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q
            if e_v != self.e:
                src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()