# This file contains tests that mock malicious users that force the protocol to abort during the
# signature phase

import pytest
from PoC_DSA.src.entities import User1, User2, RecoveryParty
import unittest.mock as mock
import PoC_DSA.src.utils
import PoC_DSA.src.general_procedures
import PoC_DSA.src.main

# This test mocks a failed check on the signature (wrong e value i.e.) for user1
def test_signature_validity_fail_user1():
    def mock_combine_user1(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("s_i", self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            self.s = (self.s_1 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = PoC_DSA.src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            # Add 1 to e_v
            e_v = (e_v + 1) % self.q

            if e_v != self.e:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(User1, 'combine', new=mock_combine_user1):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check on the signature (wrong e value i.e.) for user2
def test_signature_validity_fail_user2():
    def mock_combine_user2(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("s_i", self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            self.s = (self.s_2 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = PoC_DSA.src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            # Add 1 to e_v
            e_v = (e_v + 1) % self.q

            if e_v != self.e:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(User2, 'combine', new=mock_combine_user2):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks the failure of the verification of the commitment in combine of user1
def test_combine_commitment_verification_fail_user1():
    def mock_combine_user1(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment

        # Add 1 to the decommitment (or the commitment, just the same) to make verification fail
        self.other_s_decommitment = ((self.other_s_decommitment[0] + 1) % self.q, self.other_s_decommitment[1])

        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("s_i", self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            self.s = (self.s_1 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = PoC_DSA.src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            if e_v != self.e:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(User1, 'combine', new=mock_combine_user1):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks the failure of the verification of the commitment in combine of user2
def test_combine_commitment_verification_fail_user2():
    def mock_combine_user2(self, other_s_decommitment):
        self.other_s_decommitment = other_s_decommitment

        # Add 1 to the decommitment (or the commitment, just the same) to make verification fail
        self.other_s_decommitment = ((self.other_s_decommitment[0] + 1) % self.q, self.other_s_decommitment[1])

        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("s_i",self.other_s_commitment, other_s_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            self.s = (self.s_2 + self.other_s_decommitment[0]) % self.q
            
            # Verification
            r_v = (pow(self.g, self.s, self.p) * pow(self.A, self.e, self.p)) % self.p
            e_v = PoC_DSA.src.crypto_utils.hash_message(r_v, self.msg_to_sign, self.q) % self.q

            if e_v != self.e:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.signature = (self.e, self.s)
                self.signature_completed.set()

    with mock.patch.object(User2, 'combine', new=mock_combine_user2):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when R=1 for user1
def test_signature_validity_fail_R_equals_1_user1():
    def mock_signature_3_part2_user1(self):
        self.R = (self.R_1 * self.other_R_decommitment[0]) % self.p

        # Modification to make R=1
        self.R = 1
        # If R=1 the protocol aborts, since it would cause problems in the following computations
        if self.R == 1:
            PoC_DSA.src.general_procedures.abort()

        # Compute e = H(m || R) mod q
        self.e = PoC_DSA.src.crypto_utils.hash_message(self.R, self.msg_to_sign, self.q) % self.q

        # Compute s_1 = k_1 - e * omega_1 mod q
        self.s_1 = (self.k_1 - self.e * self.omega_1) % self.q

        # Compute the commitment for s_1
        s_1_commitment, s_1_decommitment = PoC_DSA.src.crypto_utils.commit_single("s_i", self.s_1, self.q)
        self.s_1_decommitment = s_1_decommitment

        # Send the commitment to the other user
        self.queue2.put(PoC_DSA.src.utils.Message(description="s_1_commitment", sender=self.party_id, receiver=2, content=s_1_commitment))
    
    with mock.patch.object(User1, 'signature_3_part2', new=mock_signature_3_part2_user1):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when R=1 for user2
def test_signature_validity_fail_R_equals_1_user2():
    def mock_signature_3_part2_user2(self):
        # Compute R = R_2* R_other mod p
        self.R = (self.other_R_decommitment[0] * self.R_2) % self.p

        # Modification to make R=1
        self.R = 1
        # If R=1, the signature would be invalid, so the protocol aborts
        if self.R == 1:
            PoC_DSA.src.general_procedures.abort()

        # Compute e = H(m || R)
        self.e = PoC_DSA.src.crypto_utils.hash_message(self.R, self.msg_to_sign, self.q) % self.q

        # Compute s_2 = k_2 - e*omega_2 mod q
        self.s_2 = (self.k_2 - self.e * self.omega_2) % self.q

        # Compute s_2 commitment
        s_2_commitment, s_2_decommitment = PoC_DSA.src.crypto_utils.commit_single("s_i", self.s_2, self.q)
        self.s_2_decommitment = s_2_decommitment

        # Send s_2 commitment to the other user
        self.queue1.put(PoC_DSA.src.utils.Message(description="s_2_commitment", sender=self.party_id, receiver=1, content=s_2_commitment))

    with mock.patch.object(User2, 'signature_3_part2', new=mock_signature_3_part2_user2):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when other_R is 1 for user1
def test_signature_validity_fail_other_R_equals_1_user1():
    def mock_signature_3_user1(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("r_i", self.other_R_commitment, other_R_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            # Add 1 to the decommitment to make the check fail
            self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
            self.signature_3_part2()

    with mock.patch.object(User1, 'signature_3', new=mock_signature_3_user1):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when other_R is 1 for user2
def test_signature_validity_fail_other_R_equals_1_user2():
    def mock_signature_3_user2(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("r_i", self.other_R_commitment, other_R_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            # Add 1 to the decommitment to make the check fail
            self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
            self.signature_3_part2()

    with mock.patch.object(User2, 'signature_3', new=mock_signature_3_user2):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")

# This test mocks a failed check when other_R_decommitment (or commitment) is wrong for user1
def test_signature_validity_fail_other_R_decommitment_wrong_user1():
    def mock_signature_3_user1(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment

        # Add 1 to the decommitment to make the check fail
        self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("r_i", self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
            self.signature_3_part2()

# This test mocks a failed check when other_R_decommitment (or commitment) is wrong for user2
def test_signature_validity_fail_other_R_decommitment_wrong_user2():
    def mock_signature_3_user2(self, other_R_decommitment):
        self.other_R_decommitment = other_R_decommitment

        # Add 1 to the decommitment to make the check fail
        self.other_R_decommitment = (self.other_R_decommitment[0] + 1, self.other_R_decommitment[1])
        # Verify the commitment received from the other user
        if not PoC_DSA.src.crypto_utils.verify_commitment("r_i", self.other_R_commitment, self.other_R_decommitment):
            # The protocol aborts
            PoC_DSA.src.general_procedures.abort()
        else:
            if self.other_R_decommitment[0] == 1:
                # The protocol aborts if R_2=1 or R_3=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
            self.signature_3_part2()

    with mock.patch.object(User2, 'signature_3', new=mock_signature_3_user2):
        try: 
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.ProtocolAbortedException:
            assert True
        else:
            pytest.fail("Protocol did not abort as expected")