# Copyright (C) 2014 Peter Todd <pete@petertodd.org>
#
# This file is part of Timelock.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of Timelock, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import bitcoin.core
import bitcoin.wallet
import hashlib
import os
import time

import timelock.kernel

def xor_bytes(a, b):
    """Bytewise XOR"""
    if len(a) != len(b):
        raise ValueError('a and b must be same length')

    return bytes([a[i] ^ b[i] for i in range(len(a))])

class TimelockChain:
    # Hash algorithm
    algorithm = None

    # initialization vector
    iv = None

    # total # of hashes
    n = None

    seckey = None
    secret = None

    # hash of the secret
    hashed_secret = None

    # current step # and state of the chain computation
    i = None
    midstate = None

    def __init__(self, n, iv=None, encrypted_iv=None, algorithm=timelock.kernel.AlgorithmSHA256):
        """Create a new timelock chain"""

        self.n = n
        self.algorithm = algorithm
        self.iv = iv
        self.encrypted_iv = encrypted_iv

        self.i = 0
        self.midstate = self.iv

    @staticmethod
    def midstate_to_seckey(midstate):
        return bitcoin.wallet.CBitcoinSecret.from_secret_bytes(midstate)

    @staticmethod
    def seckey_to_secret(seckey):
        return hashlib.sha256(seckey.pub).digest()

    @staticmethod
    def secret_to_hashed_secret(secret):
        return hashlib.new('ripemd160', secret).digest()

    def encrypt_iv(self, prev_secret):
        if self.iv is None:
            raise ValueError('Decrypted IV not available')
        self.encrypted_iv = xor_bytes(self.iv, prev_secret)

    def decrypt_iv(self, prev_secret):
        if self.encrypted_iv is None:
            raise ValueError('Encrypted IV not available')
        self.iv = xor_bytes(self.encrypted_iv, prev_secret)
        self.midstate = self.iv
        self.i = 0

    def add_secret(self, secret):
        """Update chain with newly discovered secret

        Returns True on success, False otherwise
        """
        if self.hashed_secret is None:
            raise ValueError("Can't add secret if chain not yet computed!")

        if self.hashed_secret == self.secret_to_hashed_secret(secret):
            self.secret = secret
            return True

        else:
            return False

    def add_pubkey_secret(self, pubkey_secret):
        """Add newly discovered pubkey secret to chain"""
        secret = hashlib.sha256(pubkey_secret).digest()
        return self.add_secret(secret)

    def add_seckey(self, seckey):
        """Add newly discovered seckey secret to chain

        Returns True on succese, False otherwise
        """
        return self.add_pubkey_secret(seckey.pub)


    def unlock(self, t, j = None):
        """Unlock the timelock for up to t seconds

        j - Optionally stop the computation at a specific index

        Returns True if the timelock is now unlocked, False otherwise.
        """
        if self.i == 0:
            self.midstate = self.iv

        if self.midstate is None:
            import pdb; pdb.set_trace()
            raise ValueError("Can't unlock chain: midstate not available")

        start_time = time.monotonic()

        if j is None:
            j = self.n

        if j > self.n:
            raise ValueError('j > self.n')

        max_m = 1
        while self.i < j and time.monotonic() - start_time < t:
            t0 = time.monotonic()

            m = min(j - self.i, max_m)
            # FIXME: need some kind of "fastest kernel" thing here
            self.midstate = self.algorithm.KERNELS[-1].run(self.midstate, m)
            self.i += m

            if time.monotonic() - t0 < 0.025:
                max_m *= 2

        assert self.i <= self.n

        if self.i == self.n:
            # Done! Create the secret key, secret, and finally hashed
            # secret.
            self.seckey = self.midstate_to_seckey(self.midstate)
            self.secret = self.seckey_to_secret(self.seckey)
            self.hashed_secret = self.secret_to_hashed_secret(self.secret)

        return self.secret is not None




class Timelock:
    chains = None

    VERSION = 1

    @property
    def secret(self):
        return self.chains[-1].secret

    def __init__(self, num_chains, n, algorithm=timelock.kernel.AlgorithmSHA256, ivs=None):
        """Create a new timelock

        num_chains - # of chains
        n          - # of hashes for each chain
        """

        if ivs is None:
            ivs = [os.urandom(algorithm.NONCE_LENGTH) for i in range(num_chains)]
        self.chains = [TimelockChain(n, iv=ivs[i], algorithm=algorithm) for i in range(num_chains)]

    def to_json(self):
        """Convert to JSON-compatible primitives"""

        def nb2x(b):
            if b is None:
                return b
            else:
                return bitcoin.core.b2x(b)

        r = {}

        r['version'] = self.VERSION

        json_chains = []
        for chain in self.chains:
            json_chain = {}

            json_chain['algorithm'] = chain.algorithm.SHORT_NAME

            json_chain['iv'] = nb2x(chain.iv)
            json_chain['encrypted_iv'] = nb2x(chain.encrypted_iv)

            json_chain['n'] = chain.n
            json_chain['i'] = chain.i
            json_chain['midstate'] = nb2x(chain.midstate)

            json_chain['hashed_secret'] = None
            if chain.hashed_secret is not None:
                json_chain['hashed_secret'] = str(bitcoin.wallet.CBitcoinAddress.from_bytes(chain.hashed_secret, 0))

            json_chain['seckey'] = str(chain.seckey) if chain.seckey is not None else None
            json_chain['secret'] = nb2x(chain.secret)

            json_chains.append(json_chain)

        r['chains'] = json_chains

        return r


    @classmethod
    def from_json(cls, obj):
        """Convert from JSON-compatible primitives"""
        self = cls.__new__(cls)

        def nx(x):
            if x is None:
                return None
            else:
                return bitcoin.core.x(x)

        if obj['version'] != self.VERSION:
            raise ValueError('Bad version!')

        self.chains = []
        for json_chain in obj['chains']:
            algorithm = timelock.kernel.ALGORITHMS_BY_NAME[json_chain['algorithm']]
            chain = TimelockChain(json_chain['n'],
                                iv=nx(json_chain['iv']),
                                encrypted_iv=nx(json_chain['encrypted_iv']),
                                algorithm=algorithm)

            chain.i = json_chain['i']
            chain.midstate = nx(json_chain['midstate'])

            chain.hashed_secret = json_chain['hashed_secret']
            if chain.hashed_secret is not None:
                chain.hashed_secret = bitcoin.wallet.CBitcoinAddress(chain.hashed_secret)

            chain.secret = nx(json_chain['secret'])

            chain.seckey = json_chain['seckey']
            if chain.seckey is not None:
                chain.seckey = bitcoin.wallet.CBitcoinSecret(chain.seckey)

            self.chains.append(chain)

        return self

    def make_locked(self):
        """Create a locked timelock from a fully computed timelock

        Returns a new timelock
        """
        # Make sure every chain is fully computed
        for (i, chain) in enumerate(self.chains):
            if not chain.unlock(0):
                raise ValueError("Chain %d is still locked" % i)

            if 0 < i:
                # Encrypt IV with previous secret
                chain.encrypt_iv(self.chains[i-1].secret)

        locked = self.__class__.__new__(self.__class__)

        locked.chains = []

        for unlocked_chain in self.chains:
            locked_chain = TimelockChain(unlocked_chain.n,
                    iv=None, encrypted_iv=unlocked_chain.encrypted_iv,
                    algorithm=unlocked_chain.algorithm)
            locked_chain.hashed_secret = unlocked_chain.hashed_secret
            locked.chains.append(locked_chain)

        locked.chains[0].iv = self.chains[0].iv

        return locked

    def add_secret(self, secret):
        """Add newly discovered secret

        All chains will be attempted.

        Returns True on success, False on failure
        """
        for chain in self.chains:
            if chain.hashed_secret is None:
                raise ValueError("Can't add secret if chain not yet computed!")

            if chain.add_secret(secret):
                return True
            if chain.add_pubkey_secret(secret):
                return True
            if hasattr(secret, 'pub') and chain.add_seckey_secret(secret):
                return True

        return False


    def unlock(self, t, from_first_chain=False):
        """Unlock the timelock for up to t seconds

        from_first_chain - Start at front rather than back.

        Returns True if the timelock is now unlocked, False if otherwise
        """
        start_time = time.monotonic()

        while self.secret is None and time.monotonic() - start_time < t:

            enum_chains = tuple(enumerate(self.chains))

            # If we don't care about unlocking all chains we can start at the
            # last chain instead and work backwards.
            if not from_first_chain:
                enum_chains = reversed(enum_chains)

            for (i, chain) in enum_chains:
                if chain.secret is not None:
                    continue

                if chain.iv is None:
                    assert(i > 0)

                    # Can we decrypt iv with previous chain's secret?
                    prev_chain = self.chains[i-1]
                    if prev_chain.secret is not None:
                        chain.decrypt_iv(prev_chain.secret)

                    else:
                        continue

                if chain.unlock(t):
                    # return early
                    t = -1

                break

        return self.secret is not None
