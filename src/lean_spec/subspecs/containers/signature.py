"""Signature container."""

from __future__ import annotations

from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.uint import Uint8

MAX_TREE_DEPTH = 64


class HashDigest(SSZVector):
    """A 32-byte hash digest."""
    ELEMENT_TYPE = Uint8
    LENGTH = 32


class Parameter(SSZVector):
    """A 32-byte parameter."""
    ELEMENT_TYPE = Uint8
    LENGTH = 32


class Randomness(SSZVector):
    """A 32-byte randomness seed."""
    ELEMENT_TYPE = Uint8
    LENGTH = 32

    @staticmethod
    def zero() -> "Randomness":
        """Return a zero-valued randomness vector."""
        return Randomness(data=[0] * Randomness.LENGTH)


class HashDigestList(SSZList):
    """A list of hash digests."""
    ELEMENT_TYPE = HashDigest
    LIMIT = MAX_TREE_DEPTH


class HashTreeOpening(Container):
    """A Merkle authentication path."""
    siblings: HashDigestList


class Signature(Container):
    """A signature produced by the `sign` function."""
    path: HashTreeOpening
    rho: Randomness
    hashes: HashDigestList

    @staticmethod
    def zero() -> "Signature":
        """Return a zero-value placeholder signature."""
        return Signature(
            path=HashTreeOpening(siblings=HashDigestList(data=[])),
            rho=Randomness.zero(),
            hashes=HashDigestList(data=[]),
        )
