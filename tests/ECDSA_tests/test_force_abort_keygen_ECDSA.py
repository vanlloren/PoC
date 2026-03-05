# This file contains all the tests that substitute some functions with mock-malicious ones to verify 
# abort procedure.

import pytest
import unittest.mock as mock
import PoC_ECDSA.src.entities
import PoC_ECDSA.src.main
import PoC_ECDSA.src.curves_utils as curves_utils
import queue
import secrets

# This test substitutes keygen_3 of player 2 with a malicious one that mimicks the receival of 
# a wrong decommitment
def test_keygen_abort_on_wrong_decommitment_p2():

    def mock_keygen_3_wrong_decommitment(self, decommitment):
    
        self.A_Y_other_decommitment = decommitment

        # Add 1 to decommitment[0] to make it wrong
        decommitment = ((decommitment[0] + 1) % self.p, decommitment[1], decommitment[2], decommitment[3], decommitment[4]) 

        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_1 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_1 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_1) or curves_utils.is_infinity(self.Y_3_1):
                # The protocol aborts if A_1=1 or Y_3_1=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_3', mock_keygen_3_wrong_decommitment):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong decommitment from player 2")

# This test substitutes keygen_3 of player 1 with a malicious one that mimicks the receival of a wrong decommitment
def test_keygen_abort_on_wrong_decommitment_p1():
    def mock_keygen_3_wrong_decommitment(self, decommitment):
        self.A_Y_other_decommitment = decommitment

        # Add 1 to decommitment[0] to make it wrong
        decommitment = ((decommitment[0] + 1) % self.p, decommitment[1], decommitment[2], decommitment[3], decommitment[4]) 

        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_2 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_2 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_2) or curves_utils.is_infinity(self.Y_3_2):
                # The protocol aborts if A_2=1 or Y_3_2=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_3', mock_keygen_3_wrong_decommitment):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong decommitment from player 1")


# This test substitutes keygen_2 of player 2 with a malicious one that mimicks the sending of a wrong commitment to player 1
def test_keygen_abort_on_wrong_commitment_p1():
    def mock_keygen_2_wrong_commitment(self, commitment):
        self.A_Y_other_commitment = commitment

        # Add 1 to the commitment to make it wrong
        com_to_int = int.from_bytes(self.A_Y_other_commitment, byteorder='big')
        new_com = com_to_int + 1 
        self.A_Y_other_commitment = new_com.to_bytes((new_com.bit_length() + 7) // 8, byteorder='big') 

        # Send the decommitment to the other user
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=1, content=self.A_Y_decommitment))

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_2', mock_keygen_2_wrong_commitment):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong commitment from player 2")

# This test substitutes keygen_2 of player 1 with a malicious one that mimicks the sending of a wrong commitment to player 2
def test_keygen_abort_on_wrong_commitment_p2():
    def mock_keygen_2_wrong_commitment(self, commitment):
        self.A_Y_other_commitment = commitment

        # Add 1 to the commitment to make it wrong
        com_to_int = int.from_bytes(self.A_Y_other_commitment, byteorder='big')
        new_com = com_to_int + 1 
        self.A_Y_other_commitment = new_com.to_bytes((new_com.bit_length() + 7) // 8, byteorder='big') 

        # Send the decommitment to the other user
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="A_Y_decommitment", sender=self.party_id, receiver=2, content=self.A_Y_decommitment))
        
    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_2', mock_keygen_2_wrong_commitment):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
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

        # Publish a fake M_1 to the other user
        M_1 = curves_utils.scalar_mult(self.m_1, self.g)
        # Generate a point different from M_1 and send it
        fake_M_1 = curves_utils.scalar_mult(2, M_1)
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="M_1", sender=self.party_id, receiver=2, content=fake_M_1))

        # Encrypt y_1_3 and y_3_1 with public key
        enc_y_1_3 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_1_3)
        enc_y_3_1 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_1)

        self.rec_1_3 = (enc_y_1_3, enc_y_3_1)

        # Send y_1_j and rec_1_3 to the other user
        self.queue2.put(PoC_ECDSA.src.utils.Message(description="rec_info", sender=self.party_id, receiver=2, content=(self.y_1_2, self.rec_1_3)))
        

    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_4', mock_keygen_4_wrong_check):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
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
        M_2 = curves_utils.scalar_mult(self.m_2, self.g)
        # Generate a fake_M_2 and add 1 to its x coordinate
        fake_M_2 = curves_utils.scalar_mult(2, M_2)
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="M_2", sender=self.party_id, receiver=1, content=fake_M_2))

        # Encrypt y_2_3 and y_3_2 with public key
        enc_y_2_3 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_2_3)
        enc_y_3_2 = PoC_ECDSA.src.crypto_utils.encrypt_with_public_key(self.recovery_public_key, self.y_3_2)

        self.rec_2_3 = (enc_y_2_3, enc_y_3_2)

        # Send y_2_1 and rec_2_3 to the other user
        # MISSING TODO: Add NIZKP
        self.queue1.put(PoC_ECDSA.src.utils.Message(description="rec_info", sender=self.party_id, receiver=1, content=(self.y_2_1, self.rec_2_3)))
        
    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_4', mock_keygen_4_wrong_check):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong M_2 from player 2")

# This test mocks keygen_5 of player 1 to check on a wrong value of y_2_1
def test_keygen_abort_on_wrong_y_2_1():
    def mock_keygen_5_wrong_y_2_1(self):
        # Add 1 to y_2_1
        self.y_2_1 = self.y_2_1 + 1
        if curves_utils.scalar_mult(self.y_2_1, self.g) != curves_utils.point_add(self.A_2, curves_utils.scalar_mult(self.M_2, 1)):
            PoC_ECDSA.src.general_procedures.abort()        

        # Generate x_1
        self.x_1 = (self.y_1_1 + self.y_2_1 + self.y_3_1) % self.q

        # ZKP to prove correct computation of x_i without revealing it should be added here
        self.zk_prove_x()

    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_5', mock_keygen_5_wrong_y_2_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong y_{i}_{j} from player 1")

# This test mocks keygen_5 of player 2 to check on a wrong value of y_1_2
def test_keygen_abort_on_wrong_y_1_2():
    def mock_keygen_5_wrong_y_1_2(self):
        # Add 1 to y_1_2
        self.y_1_2 = self.y_1_2 + 1
        if curves_utils.scalar_mult(self.y_1_2, self.g) != curves_utils.point_add(self.A_1, curves_utils.scalar_mult(self.M_1, 2)):
            PoC_ECDSA.src.general_procedures.abort()        

        # Generate x_2
        self.x_2 = (self.y_1_2 + self.y_2_2 + self.y_3_2) % self.q

        # ZKP to prove correct computation of x_2 without revealing it should be added here
        self.zk_prove_x()

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_5', mock_keygen_5_wrong_y_1_2):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on wrong y_{i}_{j} from player 2")

# This test mocks the situation where p1 receives A_2=point at infinity 
def test_keygen_abort_on_A_2_equal_1():
    def mock_keygen_1_A_2_equal_1(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, self.A_Y_other_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_2 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            # A_2 is changed in a point to infinity
            self.A_2 = curves_utils.point_at_infinity()
            self.Y_3_2 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_2) or curves_utils.is_infinity(self.Y_3_2):
                # The protocol aborts if A_2=1 or Y_3_2=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()


    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_3', mock_keygen_1_A_2_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on A_2 equal to point at infinity")

# This test mocks the situation where p2 receives A_1=point at infinity
def test_keygen_abort_on_A_1_equal_1():
    def mock_keygen_1_A_1_equal_1(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_1 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            # A_1 is changed in a point to infinity
            self.A_1 = curves_utils.point_at_infinity()
            self.Y_3_1 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            if curves_utils.is_infinity(self.A_1) or curves_utils.is_infinity(self.Y_3_1):
                # The protocol aborts if A_1=1 or Y_3_1=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_3', mock_keygen_1_A_1_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on A_1 equal to 1")

# This test mocks the situation where p1 receives Y_3_2=point at infinity
def test_keygen_abort_on_Y_3_2_equal_1():
    def mock_keygen_1_Y_3_2_equal_1(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, self.A_Y_other_decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_2 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_2 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            # Y_3_2 is changed in a point to infinity
            self.Y_3_2 = curves_utils.point_at_infinity()
            if curves_utils.is_infinity(self.A_2) or curves_utils.is_infinity(self.Y_3_2):
                # The protocol aborts if A_2=1 or Y_3_2=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()
        

    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'keygen_3', mock_keygen_1_Y_3_2_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on Y_3_2 equal to 1")

# This test mocks the situation where p2 receives Y_3_1=point at infinity
def test_keygen_abort_on_Y_3_1_equal_1():
    def mock_keygen_1_Y_3_1_equal_1(self, decommitment):
        self.A_Y_other_decommitment = decommitment
        # Verify the commitment received from the other user
        if not PoC_ECDSA.src.crypto_utils.verify_commitment_point(self.A_Y_other_commitment, decommitment):
            # The protocol aborts
            PoC_ECDSA.src.general_procedures.abort()
        else:
            self.A_1 = curves_utils.generate_point(self.A_Y_other_decommitment[0], self.A_Y_other_decommitment[1])
            self.Y_3_1 = curves_utils.generate_point(self.A_Y_other_decommitment[2], self.A_Y_other_decommitment[3])
            # Y_3_1 is changed in a point to infinity
            self.Y_3_1 = curves_utils.point_at_infinity()
            if curves_utils.is_infinity(self.A_1) or curves_utils.is_infinity(self.Y_3_1):
                # The protocol aborts if A_1=1 or Y_3_1=1, since it would cause problems in the following computations
                PoC_ECDSA.src.general_procedures.abort()
            self.keygen_4()

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'keygen_3', mock_keygen_1_Y_3_1_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on Y_3_1 equal to 1")

# This test mocks the situation where p1 receives M_2= point at infinity
def test_keygen_abort_on_M_2_equal_1():
    def mock_keygen_4_M_2_equal_1(self, msg):
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
                self.c = secrets.randbelow(self.q - 1) + 1
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
                self.c = secrets.randbelow(self.q - 1) + 1
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
            # M_2 is changed in a point to infinity
            self.M_2 = curves_utils.point_at_infinity()
            if curves_utils.is_infinity(self.M_2):
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

    with mock.patch.object(PoC_ECDSA.src.entities.User1, 'processMessage', mock_keygen_4_M_2_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on M_2 equal to 1")

# This test mocks keygen_4 of player 1 to generate M_1=1 (directly or choosing m_1=0)
def test_keygen_abort_on_M_1_equal_1():
    def mock_keygen_4_M_1_equal_1(self, msg):
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
                self.c = secrets.randbelow(self.q - 1) + 1
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
                self.c = secrets.randbelow(self.q - 1) + 1
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
            # M_1 is changed in a point to infinity
            self.M_1 = curves_utils.point_at_infinity()
            if curves_utils.is_infinity(self.M_1):
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

    with mock.patch.object(PoC_ECDSA.src.entities.User2, 'processMessage', mock_keygen_4_M_1_equal_1):
        try:
            PoC_ECDSA.src.main.main()
        except PoC_ECDSA.src.utils.ProtocolAbortedException:
            assert True  # Protocol should be aborted
        else:
            pytest.fail("Protocol did not abort on M_1 equal to 1")

