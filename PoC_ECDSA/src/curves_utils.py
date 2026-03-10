# This file contains utility functions to operate on the points of an elliptic curve
import ecdsa
from ecdsa import NIST256p, ellipticcurve

def scalar_mult(k, P):
    return k * P

def point_add(P, Q):
    return P + Q

# To validate a point on the elliptic curve
def validate_point(point):
    x = point.x()
    y = point.y()
    curve = NIST256p.curve
    try:
        point_new = ellipticcurve.Point(curve, x, y)
        if point_new * NIST256p.order != ellipticcurve.INFINITY:
            return False
        return True
    except:
        return False

def generate_point(x, y):
    curve = NIST256p.curve
    return ellipticcurve.Point(curve, x, y)

def is_infinity(P):
    return P == ellipticcurve.INFINITY

def negate_point(P):
    return -P

def point_at_infinity():
    return ellipticcurve.INFINITY

def is_generating_point(P):
    return P == NIST256p.generator