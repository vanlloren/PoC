# This file contains utilities

from dataclasses import dataclass

@dataclass
class Message:
    description: str   # commitment, key, etc.
    sender: int  # 1 for user1, 2 for user2, 3 for recovery party
    receiver: int  # 1 for user1, 2 for user2, 3 for recovery party
    content: any

class ProtocolAbortedException(Exception):
    pass

class SignatureException(Exception):
    pass
    