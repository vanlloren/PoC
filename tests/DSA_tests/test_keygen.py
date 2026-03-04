import pytest
import PoC_DSA.src.main
import PoC_DSA.src.general_procedures
import PoC_DSA.src.utils
import queue

# This test checks that the initalization and key generation procedures work correctly without coding errors or aborting
def test_keygen_working():
    try:
        PoC_DSA.src.main.main()
    except PoC_DSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")   


    assert True  # Placeholder assertion to ensure the test runs without errors

# This test checks if the two users compute the same value of A
def test_keygen_correct_publickey_generation():
    try:
        recovery, user1, user2, exceptionQueue, failedSignatureExceptionQueue = PoC_DSA.src.general_procedures.initialize_protocol()
        success = PoC_DSA.src.general_procedures.begin_keygen_protocol(user1, user2)

        try:
            exc = exceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        assert success, "Key generation did not complete successfully"

        # Check if the two users computed the same A_3 and A values
        assert user1.A_3 == user2.A_3, "Users did not compute the same A_3 value"
        assert user1.A == user2.A, "Users did not compute the same A value"

        # Check if A is an integer mod p
        assert isinstance(user1.A, int), "A is not an integer"
        assert 0 <= user1.A < user1.p, "A is not in the correct range [0, p-1]"
        
        # Check if A is in the Schnorr group
        assert pow(user1.A, user1.q, user1.p) == 1, "A is not in the Schnorr group"

        # Check that A, A_1, A_2, A_3 are not 1 (A=0 impossibile per costruzione)
        assert user1.A != 1, "A is 1"
        assert user1.A_1 != 1, "A_1 is 1"
        assert user2.A_2 != 1, "A_2 is 1"
        assert user1.A_3 != 1, "A_3 is 1"

    except PoC_DSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")
    finally:
        recovery.running = False
        user1.running = False
        user2.running = False

# This test checks the correctness of other values in key generation phase
def test_keygen_correctness_of_other_values():
    try:
        recovery, user1, user2, exceptionQueue, failedSignatureExceptionQueue = PoC_DSA.src.general_procedures.initialize_protocol()
        success = PoC_DSA.src.general_procedures.begin_keygen_protocol(user1, user2)

        try:
            exc = exceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        assert success, "Key generation did not complete successfully"

        # Check that the values of A_1, A_2, Y_3_1, Y_3_2 are consistent with the group parameters and the protocol steps
        assert pow(user1.g, user1.a_1, user1.p) == user1.A_1, "A_1 is not consistent with g and a_1"
        assert pow(user2.g, user2.a_2, user2.p) == user2.A_2, "A_2 is not consistent with g and a_2"
        assert pow(user1.g, user1.y_3_1, user1.p) == user1.Y_3_1, "Y_3_1 is not consistent with g and y_3_1"
        assert pow(user2.g, user2.y_3_2, user2.p) == user2.Y_3_2, "Y_3_2 is not consistent with g and y_3_2"

        # Check that omega_1 + omega_2 is equal to a_1 + a_2 + 2y_3_1 - y_3_2 mod q
        omega_sum = (user1.omega_1 + user2.omega_2) % user1.q
        expected_omega_sum = (user1.a_1 + user2.a_2 + 2 * user1.y_3_1 - user2.y_3_2) % user1.q
        assert omega_sum == expected_omega_sum, "The sum of omega_1 and omega_2 is not consistent with the expected value based on a_1, a_2, y_3_1 and y_3_2"

    except PoC_DSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")
    finally:
        recovery.running = False
        user1.running = False
        user2.running = False
