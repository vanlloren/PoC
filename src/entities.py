# This file contains the definitions of the entities used in the protocol such as RecoveryParty and User.

import src.crypto_utils

# The offline RecoveryParty
class RecoveryParty:
    # Creates a recovery party with its own RSA key pair for encryption and decryption
    def __init__(self):
        self.enc_private_key, self.enc_public_key = src.crypto_utils.generate_rsa_keypair()

    # Sets the group parameters for the recovery party
    def set_group_parameters(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

    # Shares the encryption public key of the recovery party to the list of users
    def share_encryption_public_key(self, UserList):
        for user in UserList:
            user.receive_recovery_public_key(self.enc_public_key)
        

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
        

    


        
        
        
        