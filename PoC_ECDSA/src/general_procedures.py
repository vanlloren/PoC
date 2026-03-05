# This file will contain the general procedures used in the protocol such as key generation, ordinary signature generation and recovery signature generation. These procedures will be called in the main function and in the test files to simulate the protocol and analyze its robustness against malicious adversaries.

import PoC_ECDSA.src.crypto_utils
import PoC_ECDSA.src.entities
import threading
import time
import queue
import PoC_ECDSA.src.utils
from PoC_ECDSA.src.utils import ProtocolAbortedException, SignatureException

def initialize_protocol():
    # Create queues for communication between the parties
    queue1 = queue.Queue()  # User1
    queue2 = queue.Queue()  # User2
    queue3 = queue.Queue()  # Recovery Party
    abortExceptionQueue = queue.Queue()  # To communicate abort exceptions from threads to the main thread
    failedSignatureExceptionQueue = queue.Queue()  # To communicate signature exceptions from threads to general procedures

    # Initialize the recovery party and the users
    recovery_party = PoC_ECDSA.src.entities.RecoveryParty()
    user1 = PoC_ECDSA.src.entities.User1(party_id=1)
    user2 = PoC_ECDSA.src.entities.User2(party_id=2)

    # Send the queues to the users and the recovery party
    user1.set_communication_queues(queue1, queue2, queue3, abortExceptionQueue, failedSignatureExceptionQueue)
    user2.set_communication_queues(queue1, queue2, queue3, abortExceptionQueue, failedSignatureExceptionQueue)
    recovery_party.set_communication_queues(queue1, queue2, queue3, abortExceptionQueue)

    # Generate elliptic curve parameters for the protocol
    G, p, n, name = PoC_ECDSA.src.crypto_utils.generate_elliptic_curve()

    # Set the curve parameters for all the parties
    recovery_party.set_curve_parameters(G, p, n)
    user1.set_curve_parameters(G, p, n)
    user2.set_curve_parameters(G, p, n)

    # Share the recovery party's encryption public key with the users
    recovery_party.share_encryption_public_key([user1, user2])

    recovery_party.start()
    user1.start()
    user2.start()

    return recovery_party, user1, user2, abortExceptionQueue, failedSignatureExceptionQueue

# This function aborts the protocol 
def abort():
    raise PoC_ECDSA.src.utils.ProtocolAbortedException("Protocol aborted due to an error or malicious behavior.")

# This function raises a SignatureException
def raise_signature_exception(guilty_party_id):
    raise PoC_ECDSA.src.utils.SignatureException(f"Signature generation failed due to malicious behavior of user{guilty_party_id}.")

# This function simulates the key generation protocol between two users
def begin_keygen_protocol(user1, user2):
    # Send to user1 and user2 the message to start the key generation protocol
    msg = PoC_ECDSA.src.utils.Message(description="start_keygen", sender=0, receiver=0, content=None)
    user1.queue1.put(msg)
    user2.queue2.put(msg)

    timeout = 10  # secondi
    success1 = user1.keygen_completed.wait(timeout)
    success2 = user2.keygen_completed.wait(timeout)
    
    return success1 and success2

def sign(user1, user2, msg, failedSignatureExceptionQueue, abortExceptionQueue):
    try:
        success = PoC_ECDSA.src.general_procedures.begin_signature_protocol(user1, user2, msg)

        try: 
            # Check if any of the threads has put a SignatureException in the failedSignatureExceptionQueue
            exc, guilty = failedSignatureExceptionQueue.get_nowait() # will return a couple (exception, guilty_party_id)

            # Readd the exception in the queue to be caught in main function
            failedSignatureExceptionQueue.put((exc, guilty))
            raise exc
        except queue.Empty:
            pass

        try:
            # Check if any of the threads has put an exception in the abortExceptionQueue
            exc = abortExceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        if success and user1.signature == user2.signature:
            print("Signature generation completed successfully!")
            # Print the signature (S, E) for the message
            print("Signature: ", user1.signature)
        else:            
            print("Signature generation failed!")

    except SignatureException as e:
        # Stampa messaggio di errore che indica il colpevole (user1 o user2) e l'eccezione di firma
        print(f"Main: eccezione di firma - colpevole: user{guilty}, eccezione: {e}")
        print("Main: suggerimento - eseguire il protocollo di firma di recupero per generare una firma valida per il messaggio.")

# This function simulates the ordinary signature generation protocol between two users
def begin_signature_protocol(user1, user2, msg):
    # Send to user1 and user2 the message to start the signature generation protocol
    message = PoC_ECDSA.src.utils.Message(description="start_signature", sender=0, receiver=0, content=msg)
    user1.queue1.put(message)
    user2.queue2.put(message)

    # if one of the users does not/cannot participate, a SignatureException is insterted in the
    # failedSignatureExceptionQueue, which will be caught in the main function, and the protocol will suggest to perform 
    # a recovery signature

    timeout = 10  # secondi
    success1 = user1.signature_completed.wait(timeout)
    success2 = user2.signature_completed.wait(timeout)

    user1.signature_completed.clear()  # Reset the event for the next signature
    user2.signature_completed.clear()  # Reset the event for the next signature

    return success1 and success2

def recoverySign(user, recovery_party, msg, failedSignatureExceptionQueue, abortExceptionQueue):
    try:
        success = PoC_ECDSA.src.general_procedures.begin_recovery_signature_protocol(user, recovery_party, msg, failedSignatureExceptionQueue, abortExceptionQueue)

        try: 
            # Check if any of the threads has put a SignatureException in the failedSignatureExceptionQueue
            exc, guilty = failedSignatureExceptionQueue.get_nowait() # will return a couple (exception, guilty_party_id)

            # Readd the exception in the queue to be caught in main function
            failedSignatureExceptionQueue.put((exc, guilty))
            raise exc
        except queue.Empty:
            pass

        try:
            # Check if any of the threads has put an exception in the abortExceptionQueue
            exc = abortExceptionQueue.get_nowait()
            raise exc
        except queue.Empty:
            pass

        if success and user.signature == recovery_party.signature:
            print("Recovery signature generation completed successfully!")
            # Print the signature (S, E) for the message
            print("Signature: ", user.signature)
        elif success and user.signature != recovery_party.signature:
            print("Recovery signature generation completed, but the signatures do not match!")
        else:           
            print("Recovery signature generation failed!")

    except PoC_ECDSA.src.utils.SignatureException as e:
        # Stampa messaggio di errore che indica il colpevole (user1 o user2) e l'eccezione di firma
        print(f"Main: eccezione di firma - colpevole: user{guilty}, eccezione: {e}")
        print("Main: suggerimento - eseguire il protocollo di firma di recupero per generare una firma valida per il messaggio.")

def begin_recovery_signature_protocol(user, recovery_party, msg, failedSignatureExceptionQueue, abortExceptionQueue):
    # Send to user (1 or 2) the message to start the recovery signature generation protocol
    message = PoC_ECDSA.src.utils.Message(description="start_recovery_signature", sender=0, receiver=0, content=msg)
    if user.party_id == 1:
        user.queue1.put(message)
    elif user.party_id == 2:
        user.queue2.put(message)
    else:
        raise PoC_ECDSA.src.utils.ProtocolAbortedException("Invalid user party_id. Must be 1 or 2.")
    

    # if the user does not/cannot participate, a SignatureException is insterted in the
    # failedSignatureExceptionQueue, which will be caught in the main function, and the protocol will suggest to perform 
    # a recovery signature

    timeout = 10  # secondi
    success1 = user.signature_completed.wait(timeout)
    success2 = recovery_party.signature_completed.wait(timeout)

    user.signature_completed.clear()  # Reset the event for the next signature
    recovery_party.signature_completed.clear()  # Reset the event for the next signature

    return success1 and success2