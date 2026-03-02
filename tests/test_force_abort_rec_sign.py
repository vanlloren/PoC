# This file contains the tests for the case that need the protocol to abort during recovery signature
# Obviuosly, the RecoveryParty is never malicious.

import pytest
import unittest.mock as mock
import src.entities
import src.general_procedures
import src.main
from src.utils import ProtocolAbortedException, SignatureException

# This test mocks a failed check on the signature (wrong e value i.e.) in the combine function of 
# the RecoveryParty.
def test_signature_validity_fail():
    def mock_combine_rec(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.s = (self.s_3 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            # Add 1 to e_v to fail the check
            e_v = (e_v + 1) % self.q

            if e_v != self.e:
                src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(src.entities.RecoveryParty, 'combine', new=mock_combine_rec):
        try: 
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks the failure of the verification of the commitment in combine 
# of the RecoveryParty, which should lead to the protocol aborting.
def test_combine_commitment_verification_fail():
    def mock_combine_rec(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Add 1 to the commitment to fail the verification
        self.other_s_commitment = (self.other_s_commitment + 1) % self.q
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            self.s = (self.s_3 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            if e_v != self.e:
                src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(src.entities.RecoveryParty, 'combine', new=mock_combine_rec):
        try: 
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when R=1 for RecoveryParty, in signature_3_part_2
def test_signature_3_part_2_R_equals_1_fail():
    def mock_signature_3_part2_rec(self):
        # Compute R = R_3 * R_other mod p
        self.R = (self.R_3 * self.other_R_decommitment[0]) % self.p

        # Modify R to be 1 to fail the check
        self.R = 1
        # If R=1 the protocol aborts, since it would cause problems in the following computations
        if self.R == 1:
            src.general_procedures.abort()

        # Compute e = H(m || R) mod q
        self.e = src.crypto_utils.hash_message(self.R, self.msg_to_sign, self.q) % self.q

        # Compute s_3 = k_3 - e * omega_3 mod q
        self.s_3 = (self.k_3 - self.e * self.omega_3) % self.q

        # Compute the commitment for s_3
        s_3_commitment, s_3_decommitment = src.crypto_utils.commit_single(self.s_3, self.q)
        self.s_3_decommitment = s_3_decommitment

        # Send the commitment to the other user
        if self.curr_user == 2:
            self.queue2.put(src.utils.Message(description="s_3_commitment", sender=self.party_id, receiver=2, content=s_3_commitment))
        elif self.curr_user == 1:
            self.queue1.put(src.utils.Message(description="s_3_commitment", sender=self.party_id, receiver=1, content=s_3_commitment))


    with mock.patch.object(src.entities.RecoveryParty, 'signature_3_part2', new=mock_signature_3_part2_rec):
        try: 
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when other_R is 1 for RecoveryParty, in signature_3
def test_signature_validity_fail_other_R_equals_1():
    def mock_signature_3_rec(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            # Set other_R to 1 to fail the check
            self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                src.general_procedures.abort()
            self.signature_3_part2()
    
    with mock.patch.object(src.entities.RecoveryParty, 'signature_3', new=mock_signature_3_rec):
        try: 
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when other_R_decommitment (or commitment) is wrong for RecoveryParty
# in signature_3, which should lead to the protocol aborting.
def test_signature_3_rec_wrong_other_R_decommitment():
    def mock_signature_3_rec(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Add 1 to the decommitment to make the check fail
        self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
        # Verify the commitment received from the other user
        if not src.crypto_utils.verify_commitment(self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            src.general_procedures.abort()
        else:
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                src.general_procedures.abort()
            self.signature_3_part2()

    with mock.patch.object(src.entities.RecoveryParty, 'signature_3', new=mock_signature_3_rec):
        try: 
            src.main.main()
        except src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")