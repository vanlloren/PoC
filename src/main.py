# This file contains the main function that simulates the correct functioning of the protocol.
# The analysis of robustness against malicious adversaries is done in the test files.

from src.entities import RecoveryParty, User
import src.crypto_utils
import src.general_procedures

def main():
    # Initialize the protocol, perform key generation and get the recovery party and the users
    recovery, user1, user2 = initialize_protocol()
    src.general_procedures.begin_keygen_protocol(user1, user2)

    # Simulate eventual signature here
