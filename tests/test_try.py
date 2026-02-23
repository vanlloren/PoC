import pytest

def test_che_passa_sempre():
    """Questo test passa sempre"""
    assert 1 + 1 == 2

def test_che_fallisce_se_vuoi():
    """Questo test fallisce se vuoi testare il fallimento"""
    # assert 2 + 2 == 5  # Decommenta per vedere un fallimento
    pass