import pytest
import PoC_ECDSA.src.main
import PoC_ECDSA.src.general_procedures
import PoC_ECDSA.src.utils
import PoC_ECDSA.src.curves_utils as curves_utils
import queue

# This test checks that the initalization and key generation procedures work correctly without coding errors or aborting
def test_keygen_working():
    try:
        PoC_ECDSA.src.main.main()
    except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")   


    assert True  # Placeholder assertion to ensure the test runs without errors

# This test checks if the two users compute the same value of A
def test_keygen_correct_publickey_generation():
    try:
        recovery, user1, user2, exceptionQueue, failedSignatureExceptionQueue = PoC_ECDSA.src.general_procedures.initialize_protocol()
        success = PoC_ECDSA.src.general_procedures.begin_keygen_protocol(user1, user2)

        try:
            exc = exceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        assert success, "Key generation did not complete successfully"

        # Check if the two users computed the same A_3 and A values
        assert user1.A_3 == user2.A_3, "Users did not compute the same A_3 value"
        assert user1.A == user2.A, "Users did not compute the same A value"
        
        # Check if A is in the elliptic curve
        assert curves_utils.validate_point(user1.A), "A is not in the elliptic curve"

        # Check that A, A_1, A_2, A_3 are not points at infinity (A=0 impossibile per costruzione)
        assert not curves_utils.is_infinity(user1.A), "A is at infinity"
        assert not curves_utils.is_infinity(user1.A_1), "A_1 is at infinity"
        assert not curves_utils.is_infinity(user2.A_2), "A_2 is at infinity"
        assert not curves_utils.is_infinity(user1.A_3), "A_3 is at infinity"

    except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")
    finally:
        recovery.running = False
        user1.running = False
        user2.running = False

# This test checks the correctness of other values in key generation phase
def test_keygen_correctness_of_other_values():
    try:
        recovery, user1, user2, exceptionQueue, failedSignatureExceptionQueue = PoC_ECDSA.src.general_procedures.initialize_protocol()
        success = PoC_ECDSA.src.general_procedures.begin_keygen_protocol(user1, user2)

        try:
            exc = exceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        assert success, "Key generation did not complete successfully"

        # Check that omega_1 + omega_2 is equal to a_1 + a_2 + 2y_3_1 - y_3_2 mod q
        omega_sum = (user1.omega_1 + user2.omega_2) % user1.q
        expected_omega_sum = (user1.a_1 + user2.a_2 + 2 * user1.y_3_1 - user2.y_3_2) % user1.q
        assert omega_sum == expected_omega_sum, "The sum of omega_1 and omega_2 is not consistent with the expected value based on a_1, a_2, y_3_1 and y_3_2"

    except PoC_ECDSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")
    finally:
        recovery.running = False
        user1.running = False
        user2.running = False
