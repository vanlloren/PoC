# PoC

This private repository contains a Proof of Concept (PoC) implementation of a threshold Schnorr signature scheme.

The version of the Signature Algorithm using Schnorr's groups is named PoC_DSA and running main.py in PoC_DSA\src simulates a non-malicious iteration of such protocol.
Tests in tests\DSA_tests instead focus on enforcing malicious behaviours of one of the two parties to prove the resiliency of the whole protocol.

The version of the Signature Algorithm using Elliptic Curves is named PoC_ECDSA and running main.py in PoC_ECDSA\src simulates a non-malicious iteration of such protocol.
Tests in tests\ECDSA_tests focus instead on enforcing malicious behaviours of one of the two parties to prove the resiliency of the whole protocol.