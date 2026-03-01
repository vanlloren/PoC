# This file contains tests that simulate a malicious behaviour of one user during the signature
# phase. In this file there are only behaviours that DO NOT cause the abortion of the protocol

import pytest
import unittest.mock as mock
from src.entities import User1, User2, RecoveryParty
import src.general_procedures

# This test mimicks a signature failure by player 2 before or inside signature_1
def test_malicious_signature_before_signature_1_user2():
    def mock_process_message_user2(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            # Do not call signature_1, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
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

        with mock.patch_object(User2, "process_message", new=mock_process_message_user2):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside signature_2
def test_malicious_signature_before_signature_2_user2():
    def mock_process_message_user2(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.signature_1(msg.content)
        if msg.description == "signature_fail" and msg.sender == 1:
            self.signature_completed.set()
        if msg.description == "A_Y_commitment" and msg.sender == 1:
            # Do not call keygen_2, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
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
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

        with mock.patch_object(User2, "process_message", new=mock_process_message_user2):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside signature_3
def test_malicious_signature_before_signature_3_user2():
    def mock_process_message_user2(self, msg):
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
            # Do not call signature_3, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

        with mock.patch_object(User2, "process_message", new=mock_process_message_user2):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside signature_4
def test_malicious_signature_before_signature_4_user2():
    def mock_process_message_user2(self, msg):
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
            # Do not call signature_4, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

        with mock.patch_object(User2, "process_message", new=mock_process_message_user2):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside combine
def test_malicious_signature_before_combine_user2():
    def mock_process_message_user2(self, msg):
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
            # Do not call combine, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)

        with mock.patch_object(User2, "process_message", new=mock_process_message_user2):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 1 before or inside signature_1
def test_malicious_signature_before_signature_1_user1():
    def mock_process_message_user1(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            # Do not call signature_1, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
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

        with mock.patch_object(User1, "process_message", new=mock_process_message_user1):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 1 before or inside signature_2
def test_malicious_signature_before_signature_2_user1():
    def mock_process_message_user1(self, msg):
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
            # Do not call signature_2, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "R_2_decommitment" and msg.sender == 2) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_2_commitment" and msg.sender == 2) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_2_decommitment" and msg.sender == 2) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)  

        with mock.patch_object(User1, "process_message", new=mock_process_message_user1):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 1 before or inside signature_3
def test_malicious_signature_before_signature_3_user1():
    def mock_process_message_user1(self, msg):
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
            # Do not call signature_3, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_2_commitment" and msg.sender == 2) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_2_decommitment" and msg.sender == 2) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)  

        with mock.patch_object(User1, "process_message", new=mock_process_message_user1):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 1 before or inside signature_4
def test_malicious_signature_before_signature_4_user1():
    def mock_process_message_user1(self, msg):
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
            # Do not call signature_4, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_2_decommitment" and msg.sender == 2) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)  

        with mock.patch_object(User1, "process_message", new=mock_process_message_user1):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 1 before or inside combine
def test_malicious_signature_before_combine_user1():
    def mock_process_message_user1(self, msg):
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
            # Do not call combine, but put an exception in the failedSignatureExceptionQueue
            src.general_procedures.raise_signature_exception(self.party_id)

        with mock.patch_object(User1, "process_message", new=mock_process_message_user1):
            try:
                src.main.main()
            except src.utils.SignatureException as e:
                assert True
            else:
                pytest.fail("Expected SignatureException was not raised")
