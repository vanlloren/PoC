# This file will contain the general procedures used in the protocol such as key generation, ordinary signature generation and recovery signature generation. These procedures will be called in the main function and in the test files to simulate the protocol and analyze its robustness against malicious adversaries.

import src.crypto_utils
import src.entities
import threading
import time
import queue
import src.utils

def initialize_protocol():
    # Create queues for communication between the parties
    queue1 = queue.Queue()  # User1
    queue2 = queue.Queue()  # User2
    queue3 = queue.Queue()  # Recovery Party
    exceptionQueue = queue.Queue()  # To communicate exceptions from threads to the main thread

    # Initialize the recovery party and the users
    recovery_party = src.entities.RecoveryParty()
    user1 = src.entities.User1(party_id=1)
    user2 = src.entities.User2(party_id=2)

    # Send the queues to the users and the recovery party
    user1.set_communication_queues(queue1, queue2, queue3, exceptionQueue)
    user2.set_communication_queues(queue1, queue2, queue3, exceptionQueue)
    recovery_party.set_communication_queues(queue1, queue2, queue3, exceptionQueue)

    # Generate group parameters (p, q, g) for the protocol
    p, q, g = src.crypto_utils.generate_schnorr_group()

    # Set the group parameters for all the parties
    recovery_party.set_group_parameters(p, q, g)
    user1.set_group_parameters(p, q, g)
    user2.set_group_parameters(p, q, g)

    # Share the recovery party's encryption public key with the users
    recovery_party.share_encryption_public_key([user1, user2])

    recovery_party.start()
    user1.start()
    user2.start()

    return recovery_party, user1, user2, exceptionQueue

# This function aborts the protocol 
def abort():
    raise src.utils.ProtocolAbortedException("Protocol aborted due to an error or malicious behavior.")

# This function simulates the key generation protocol between two users
def begin_keygen_protocol(user1, user2):
    # Send to user1 and user2 the message to start the key generation protocol
    msg = src.utils.Message(description="start_keygen", sender=0, receiver=0, content=None)
    user1.queue1.put(msg)
    user2.queue2.put(msg)

    timeout = 10  # secondi
    success1 = user1.keygen_completed.wait(timeout)
    success2 = user2.keygen_completed.wait(timeout)
    
    
    
    return success1 and success2