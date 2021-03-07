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

import hashlib
import logging
import time

ALGORITHMS = []
ALGORITHMS_BY_NAME = {}

class Algorithm:
    """Kernel algorithm"""
    SHORT_NAME = None
    NONCE_LENGTH = None
    KERNELS = None
    KERNELS_BY_NAME = None

    TEST_VECTORS = None

    @classmethod
    def def_kernel(cls, kernel_cls):
        kernel_cls.ALGORITHM = cls
        if cls.KERNELS == None:
            cls.KERNELS = []
            cls.KERNELS_BY_NAME = {}
        cls.KERNELS.append(kernel_cls)
        cls.KERNELS_BY_NAME[kernel_cls.SHORT_NAME] = kernel_cls
        return cls

def def_algorithm(cls):
    ALGORITHMS.append(cls)
    ALGORITHMS_BY_NAME[cls.SHORT_NAME] = cls
    return cls

@def_algorithm
class AlgorithmSHA256(Algorithm):
    SHORT_NAME = 'sha256'
    NONCE_LENGTH = 32

    TEST_VECTORS = (
        (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
         1,
         b'fhz\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d\r_)%'),
        (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
         2,
         b'+2\xdbl,\nb5\xfb\x13\x97\xe8"^\xa8^\x0f\x0en\x8c{\x12m\x00\x16\xcc\xbd\xe0\xe6g\x15\x1e',
        ),
    )


class Kernel:
    SHORT_NAME = None
    DESCRIPTION = None
    ALGORITHM = None


    @classmethod
    def run(nonce, n):
        """Run a kernel

        nonce    - starting nonce
        n        - # of iterations
        """
        raise NotImplementedError

    @classmethod
    def benchmark(cls, runtime=1.0, num_runs=3):
        """Benchmark kernel

        runtime - # of seconds per run
        num_runs - # of runs to perform

        Returns list of hashes/second for each run.
        """
        start_time = time.monotonic()

        def time_run(n):
            start_time = time.monotonic()
            cls.run(b'\x00'*cls.ALGORITHM.NONCE_LENGTH, n)
            return time.monotonic() - start_time

        # We don't want individual runs to be too short, so first find how many
        # iterations we need for a run to take 0.1 seconds.
        n = 1
        dt = 0
        while dt < 0.1:
            n *= 2
            dt = time_run(n)

        approx_hashes_per_second = n / dt

        n = int(runtime * approx_hashes_per_second)
        run_results = []
        for i in range(num_runs):
            dt = time_run(n)

            hash_per_second = n / dt
            run_results.append(hash_per_second)
            logging.info('Run %d/%d: %.3f Mhash/s' % (i+1, num_runs, hash_per_second/1000000))

        return run_results


@AlgorithmSHA256.def_kernel
class PythonSHA256(Kernel):
    SHORT_NAME = 'python'
    DESCRIPTION = 'Native Python implementation. Very slow!'

    @classmethod
    def run(cls, nonce, n):
        for i in range(n):
            nonce = hashlib.sha256(nonce).digest()
        return nonce

try:
    import timelock.kernels.sha256

    @AlgorithmSHA256.def_kernel
    class OpenSSLSHA256(Kernel):
        SHORT_NAME = 'openssl'
        DESCRIPTION = 'OpenSSL-using C-extension'

        @classmethod
        def run(cls, nonce, n):
            return timelock.kernels.sha256.run(nonce, n)

except ImportError:
    pass
