#  This file contains tests that simulate a malicious behaviour of one user during the recovery signature
# phase. In this file there are only behaviours that DO NOT cause the abortion of the protocol

import pytest
from src.entities import User1, User2, RecoveryParty
import unittest.mock as mock
import src.general_procedures
import src.main

# This test mimicks a signature failure by player 2 before or inside recovery_signature_1
def test_malicious_signature_before_recovery_signature_1():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.signature_1(msg.content)
        if msg.description == "start_recovery_signature" and msg.sender == 0:
            # Do not call the function but raise a SignatureFailure exception
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

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside signature_1
def test_malicious_signature_before_signature_1():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            src.general_procedures.raise_signature_exception(self.party_id)
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

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_2
def test_malicious_signature_before_signature_2():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.signature_1(msg.content)
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
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            # Do not call the function but raise a SignatureFailure exception
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_3
def test_malicious_signature_before_signature_3():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.signature_1(msg.content)
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
            # Do not call the function but raise a SignatureFailure exception
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):    
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_4
def test_malicious_signature_before_signature_4():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.signature_1(msg.content)
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
            # Do not call the function but raise a SignatureFailure exception
            src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during combine
def test_malicious_signature_before_combine():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.signature_1(msg.content)
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
            # Do not call the function but raise a SignatureFailure exception
            src.general_procedures.raise_signature_exception(self.party_id)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            src.main.main()
        except src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")