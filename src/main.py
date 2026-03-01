# This file contains the main function that simulates the correct functioning of the protocol.
# The analysis of robustness against malicious adversaries is done in the test files.

import src.entities
import src.crypto_utils
import src.general_procedures
from src.general_procedures import abort
from src.utils import ProtocolAbortedException
import queue

def main():
    # Initialize the protocol, perform key generation and get the recovery party and the users
    try:
        recovery, user1, user2, abortExceptionQueue, failedSignatureExceptionQueue = src.general_procedures.initialize_protocol()
        success = src.general_procedures.begin_keygen_protocol(user1, user2)

        try:
            # Check if any of the threads has put an exception in the abortExceptionQueue
            exc = abortExceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        if success:
            print("A of user1: ", user1.A)
            print("A of user2: ", user2.A)
            print("Key generation completed successfully!")
        else:
            print("Key generation failed!")


        # Now simulation of an ordinary signature
        src.general_procedures.sign(user1, user2, "This is a message to be signed.", failedSignatureExceptionQueue, abortExceptionQueue)
        try:
            # Check if any of the threads has put an exception in the failedSignatureExceptionQueue
            exc, guilty = failedSignatureExceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        # Another signature, to show that the protocol can be used multiple times with the same keys
        src.general_procedures.sign(user1, user2, "This is another message to be signed.", failedSignatureExceptionQueue, abortExceptionQueue)
        try:
            # Check if any of the threads has put an exception in the abortExceptionQueue
            exc = abortExceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

    except ProtocolAbortedException as e:
        raise e
        print(f"Main: protocollo abortito - {e}")
    finally:
        # Alla fine di tutto, fermiamo i thread dei party
        #recovery.running = False
        #user1.running = False
        #user2.running = False
        True

if __name__ == "__main__":
    main()