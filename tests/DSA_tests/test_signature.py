import pytest
import PoC_DSA.src.main
from PoC_DSA.src.entities import User1, User2, RecoveryParty
from PoC_DSA.src.utils import ProtocolAbortedException, SignatureException

# This test checks if the key generation protocol runs without errors
def test_keygen_protocol_runs_without_errors():
    try:
        PoC_DSA.src.main.main()
    except PoC_DSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")   


    assert True  # Placeholder assertion to ensure the test runs without errors

# This test checks if the two users compute the same signature (e, S)
# To run this test, ensure the main function does not terminate the threads.
def test_signature_correctness():
    try:
        PoC_DSA.src.main.main()
    except PoC_DSA.src.utils.ProtocolAbortedException as e:
        pytest.fail(f"Protocol aborted unexpectedly: {e}")   

        # Verify that both users computed the same signature (e, S)
        assert User1.signature[0] == User2.signature[0] and User1.signature[1] == User2.signature[1]  

        # Verify that e is an integer mod q and S is an integer mod q
        assert isinstance(User1.signature[0], int) and 0 <= User1.signature[0] < User1.q, "e is not an integer mod q"
        assert isinstance(User1.signature[1], int) and 0 <= User1.signature[1] < User1.q, "S is not an integer mod q"
    finally:
        RecoveryParty.running = False
        User1.running = False
        User2.running = False