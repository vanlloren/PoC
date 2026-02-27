# This file contains all the tests that substitute some functions with mock-malicious ones to verify 
# abort procedure.

import pytest
import unittest.mock as mock
import src.entities
import src.main
import queue

# This test substitutes keygen_3 of player 2 with a malicious one that mimicks the receival of a wrong decommitment
def test_keygen_abort_on_wrong_decommitment_p2():

    def mock_keygen_3_wrong_decommitment(self, decommitment):
    
        self.A_Y_other_decommitment = decommitment
        # Add 1 to the decommitment to make it wrong
        decommitment = (decommitment[0], (decommitment[1] + 1) % self.q)

        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.keygen_4()

    with mock.patch.object(src.entities.User2, 'keygen_3', mock_keygen_3_wrong_decommitment):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong decommitment from player 2")

# This test substitutes keygen_3 of player 1 with a malicious one that mimicks the receival of a wrong decommitment
def test_keygen_abort_on_wrong_decommitment_p1():
    def mock_keygen_3_wrong_decommitment(self, decommitment):
    
        self.A_Y_other_decommitment = decommitment
        # Add 1 to the decommitment to make it wrong
        decommitment = (decommitment[0], (decommitment[1] + 1) % self.q)

        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.keygen_4()

    with mock.patch.object(src.entities.User1, 'keygen_3', mock_keygen_3_wrong_decommitment):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong decommitment from player 1")


# This test substitutes keygen_2 of player 2 with a malicious one that mimicks the sending of a wrong commitment to player 1
def test_keygen_abort_on_wrong_commitment_p1():
    def mock_keygen_2_wrong_commitment(self, commitment):
        self.A_Y_other_commitment = commitment

        # Add 1 to the commitment to make it wrong
        self.A_Y_other_commitment = (self.A_Y_other_commitment[0], (self.A_Y_other_commitment[1] + 1) % self.q)

        # Send the decommitment to the other user
        self.queue1.put(src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=1, content=self.A_Y_decommitment))

    with mock.patch.object(src.entities.User2, 'keygen_2', mock_keygen_2_wrong_commitment):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong commitment from player 2")

# This test substitutes keygen_2 of player 1 with a malicious one that mimicks the sending of a wrong commitment to player 2
def test_keygen_abort_on_wrong_commitment_p2():
    def mock_keygen_2_wrong_commitment(self, commitment):
        self.A_Y_other_commitment = commitment

        # Add 1 to the commitment to make it wrong
        self.A_Y_other_commitment = (self.A_Y_other_commitment[0], (self.A_Y_other_commitment[1] + 1) % self.q)

        # Send the decommitment to the other user
        self.queue2.put(src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=0, content=self.A_Y_decommitment))

    with mock.patch.object(src.entities.User1, 'keygen_2', mock_keygen_2_wrong_commitment):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong commitment from player 1")

# This test substitutes keygen_4 of player 1 with a malicious one that mimicks the sending of a wrong M_1 to player 2
def test_keygen_abort_on_wrong_check_p2():
    def mock_keygen_4_wrong_check(self):
        # Create polinomial f_1 = a_1 + m_1*X
        f_1 = lambda X: (self.a_1 + self.m_1 * X) % self.q  

        # Compute the shares y_1_2 = f_1(j) for j=1,2,3
        self.y_1_1 = f_1(1)
        self.y_1_2 = f_1(2)
        self.y_1_3 = f_1(3)      

        # Publish M_1 to the other user
        M_1 = pow(self.g, self.m_1, self.p)

        # Add 1 to M_1 to make it wrong
        M_1 = (M_1 + 1) % self.p
        self.queue2.put(src.utils.Message(description="M_1", sender=self.party_id, receiver=2, content=M_1))

        # Encrypt y_1_3 and y_3_1 with public key
        enc_y_1_3 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_1_3)
        enc_y_3_1 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_1)

        self.rec_1_3 = (enc_y_1_3, enc_y_3_1)

        # Send y_1_j and rec_1_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue2.put(src.utils.Message(description="rec_info", sender=self.party_id, receiver=2, content=(self.y_1_2, self.rec_1_3)))
        

    with mock.patch.object(src.entities.User1, 'keygen_4', mock_keygen_4_wrong_check):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong M_1 from player 1")

# This test substitutes keygen_4 of player 2 with a malicious one that mimicks the sending of a wrong M_2 to player 1
def test_keygen_abort_on_wrong_check_p1():
    def mock_keygen_4_wrong_check(self):
       # Create polinomial f_2 = a_2 + m_2*X
        f_2 = lambda X: (self.a_2 + self.m_2 * X) % self.q  

        # Compute the shares y_2_j = f_2(j) for j=1,2,3
        self.y_2_1 = f_2(1)
        self.y_2_2 = f_2(2)
        self.y_2_3 = f_2(3)      


        # Publish M_2 to the other user
        M_2 = pow(self.g, self.m_2, self.p)

        # Add 1 to M_2 to make it wrong
        M_2 = (M_2 + 1) % self.p
        self.queue1.put(src.utils.Message(description="M_2", sender=self.party_id, receiver=1, content=M_2))

        # Encrypt y_2_3 and y_3_2 with public key
        enc_y_2_3 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_2_3)
        enc_y_3_2 = src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_2)

        self.rec_2_3 = (enc_y_2_3, enc_y_3_2)

        # Send y_2_1 and rec_2_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue1.put(src.utils.Message(description="rec_info", sender=self.party_id, receiver=1, content=(self.y_2_1, self.rec_2_3)))

    with mock.patch.object(src.entities.User2, 'keygen_4', mock_keygen_4_wrong_check):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong M_2 from player 2")

# This test mocks keygen_5 of player 1 to check on a wrong value of y_2_1
def test_keygen_abort_on_wrong_y_2_1():
    def mock_keygen_5_wrong_y_2_1(self):
        # MISSING TODO: Check NIZKP

        # Add 1 to y_2_1 to make it wrong
        self.y_2_1 = (self.y_2_1 + 1) % self.q
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

    with mock.patch.object(src.entities.User1, 'keygen_5', mock_keygen_5_wrong_y_2_1):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong y_{i}_{j} from player 1")

# This test mocks keygen_5 of player 2 to check on a wrong value of y_1_2
def test_keygen_abort_on_wrong_y_1_2():
    def mock_keygen_5_wrong_y_1_2(self):
        # MISSING TODO: Check NIZKP

        # Add 1 to y_1_2 to make it wrong
        self.y_1_2 = (self.y_1_2 + 1) % self.q
        if pow(self.g, self.y_1_2, self.p) != self.A_Y_other_decommitment[0] * pow(self.M_1, 1, self.p) % self.p:
            src.general_procedures.abort()        

        # Generate x_2
        self.x_2 = (self.y_1_2 + self.y_2_2 + self.y_3_2) % self.q

        # ZKP to prove correct computation of x_i without revealing it should be added here

        # Compute public key A
        self.A_3 = pow(self.Y_3_2, 2, self.p) * pow(self.A_Y_other_decommitment[1], -1, self.p) % self.p
        self.A = (self.A_2 * self.A_Y_other_decommitment[0] * self.A_3) % self.p

        # Compute omega_2
        self.omega_2 = (2 * self.x_2) % self.q

        self.keygen_completed.set()

    with mock.patch.object(src.entities.User2, 'keygen_5', mock_keygen_5_wrong_y_1_2):
        try:
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong y_{i}_{j} from player 2")

# TODO: Add more tests for other malicious behaviors that should cause the protocol to abort, such as: