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

# TODO: Add more tests for other malicious behaviors that should cause the protocol to abort, such as:
# - test_keygen_abort_on_wrong_commitment_p2  --> mocking keygen_2 of player 1 to send a wrong commitment to player 2
# - test_keygen_abort_on_wrong_commitment_p1  --> mocking keygen_2 of player 2 to send a wrong commitment to player 1
# - test_keygen_abort_on_wrong_check_p2  --> mocking keygen_4 of player 1 to send a wrong M_1 to player 2
# - test_keygen_abort_on_wrong_check_p1  --> mocking keygen_4 of player 2 to send a wrong M_2 to player 1

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