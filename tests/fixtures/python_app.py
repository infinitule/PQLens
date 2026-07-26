"""pqlens discovery fixture (authored by pqlens, NOT third-party code).

Deliberately mixes classical asymmetric crypto for the AST scanner to find.
This file is only ever parsed with ast.parse — never imported or executed.
"""

from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519


def make_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ecdsa_p256():
    return ec.generate_private_key(ec.SECP256R1())


def make_x25519():
    return x25519.X25519PrivateKey.generate()
