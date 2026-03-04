#  This file contains tests that simulate a malicious behaviour of one user during the recovery signature
# phase. In this file there are only behaviours that DO NOT cause the abortion of the protocol

import pytest
from PoC_DSA.src.entities import User1, User2, RecoveryParty
import unittest.mock as mock
import PoC_DSA.src.general_procedures
import PoC_DSA.src.main
import PoC_DSA.src.utils
import secrets

# This test mimicks a signature failure by player 2 before or inside recovery_signature_1
def test_malicious_signature_before_recovery_signature_1():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
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
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)
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
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
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

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by player 2 before or inside signature_1
def test_malicious_signature_before_signature_1():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "start_signature" and msg.sender == 0:
            self.recovery = False
            self.curr_user = 1
            self.signature_1(msg.content)
        if msg.description == "start_signature" and msg.sender == 3:
            self.recovery = True
            self.curr_user = 3
            self.msg_content = msg.content
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)
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
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
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

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_2
def test_malicious_signature_before_signature_2():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
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
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_3
def test_malicious_signature_before_signature_3():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
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
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            self.signature_2(msg.content)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):    
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during signature_4
def test_malicious_signature_before_signature_4():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
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
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            self.signature_2(msg.content)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            self.combine(msg.content)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")

# This test mimicks a signature failure by User2 before or during combine
def test_malicious_signature_before_combine():
    def mock_process_message(self, msg):
        if msg.description == "start_keygen" and msg.sender == 0:
            self.keygen_1()
        if msg.description == "zk_proof_x" and msg.sender == 1:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue1.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=1, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 1:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue1.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=1, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 1:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.keygen_5_part3()
            else:
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "zk_proof_x" and msg.sender == 3:
            if msg.content[0] == 0 or msg.content[1] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[1] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[1], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            else:
                self.other_u = msg.content[0]
                self.other_X = msg.content[1]
                self.c = secrets.randbelow(self.q - 1) + 1
                self.queue3.put(PoC_DSA.src.utils.Message(description="zk_challenge_x", sender=self.party_id, receiver=3, content=self.c))
        if msg.description == "zk_challenge_x" and msg.sender == 3:
            self.other_c = msg.content
            self.z = self.zk_nonce + self.x_2 * self.other_c % self.q
            self.queue3.put(PoC_DSA.src.utils.Message(description="zk_response_x", sender=self.party_id, receiver=3, content=self.z))
        if msg.description == "zk_response_x" and msg.sender == 3:
            if (msg.content % self.q) != 0  and pow(self.g, msg.content, self.p) == (self.other_u * pow(self.other_X, self.c, self.p)) % self.p:
                self.signature_1(self.msg_content)
            else:
                PoC_DSA.src.general_procedures.abort()
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
            if self.M_1 == 1:
                # The protocol aborts if M_1=1, since it would cause problems in the following computations
                PoC_DSA.src.general_procedures.abort()
        if msg.description == "rec_info" and msg.sender == 1:
            y_1_2, rec_1_3 = msg.content
            self.y_1_2 = y_1_2
            self.rec_1_3 = rec_1_3
            self.keygen_5()
        if msg.description == "nizkp_proof" and msg.sender == 1:
            # Do actions
            if msg.content[0] == 0 or msg.content[3] == 0 or msg.content[4] == 0 or msg.content[7] == 0:
                PoC_DSA.src.general_procedures.abort()
            # msg.content[0] o msg.content[3] o msg.content[4] o msg.content[7] not in the group G
            elif pow(msg.content[0], self.q, self.p) != 1 or pow(msg.content[3], self.q, self.p) != 1 or pow(msg.content[4], self.q, self.p) != 1 or pow(msg.content[7], self.q, self.p) != 1:
                PoC_DSA.src.general_procedures.abort()
            elif msg.content[2] == 0 or msg.content[6] == 0:
                PoC_DSA.src.general_procedures.abort()
            else:
                if msg.content[1] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[3], msg.content[0]) or msg.content[5] != PoC_DSA.src.crypto_utils.tuple_hash(self.g, self.q, msg.content[7], msg.content[4]):
                    PoC_DSA.src.general_procedures.abort()
                elif pow(self.g, msg.content[2], self.p) != (msg.content[0] * pow(msg.content[3], msg.content[1], self.p)) % self.p or pow(self.g, msg.content[6], self.p) != (msg.content[4] * pow(msg.content[7], msg.content[5], self.p)) % self.p:
                    PoC_DSA.src.general_procedures.abort()
                else:
                    self.keygen_5_part2()
        if (msg.description == "R_1_commitment" and msg.sender == 1) or (msg.description == "R_3_commitment" and msg.sender == 3):
            self.signature_2(msg.content)
        if (msg.description == "R_1_decommitment" and msg.sender == 1) or (msg.description == "R_3_decommitment" and msg.sender == 3):
            self.signature_3(msg.content)
        if (msg.description == "s_1_commitment" and msg.sender == 1) or (msg.description == "s_3_commitment" and msg.sender == 3):
            self.signature_4(msg.content)
        if (msg.description == "s_1_decommitment" and msg.sender == 1) or (msg.description == "s_3_decommitment" and msg.sender == 3):
            # Do not call the function but raise a SignatureFailure exception
            PoC_DSA.src.general_procedures.raise_signature_exception(self.party_id)

    with mock.patch.object(User2, "processMessage", new=mock_process_message):
        try:
            PoC_DSA.src.main.main()
        except PoC_DSA.src.utils.SignatureException as e:
            assert True
        else:
            pytest.fail("Expected SignatureException was not raised")