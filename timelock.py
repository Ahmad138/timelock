#!/usr/bin/env python3

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

VERSION = '0.1.1'

import sys

if sys.version_info.major != 3:
    raise ImportError("Python3 required")

import argparse
import bitcoin.core
import bitcoin.base58
import json
import logging
import time

import timelock
import timelock.kernel

def pretty_json_dumps(obj):
    return json.dumps(obj, indent=4, sort_keys=True)

def pretty_json_dump(obj, fd):
    fd.write(pretty_json_dumps(obj))
    fd.write('\n')

# Commands

def cmd_benchmark(args):
    algo = timelock.kernel.AlgorithmSHA256

    kernels = []
    if args.kernel:
        for kernel_name in args.kernel:
            try:
                kernels.append(algo.KERNELS_BY_NAME[kernel_name])
            except KeyError:
                logging.error("Unknown kernel '%s'" % kernel_name)
                sys.exit(1)
    else:
        kernels = timelock.kernel.AlgorithmSHA256.KERNELS


    run_results = {}
    for kernel in kernels:
        logging.info("Benchmarking kernel '%s'" % kernel.SHORT_NAME)
        run_results[kernel] = kernel.benchmark(args.runtime, args.n)

    if args.verbosity >= 0:
        # FIXME: should be able to better pretty-print this
        print(' Kernel:\tmin\tavg\tmax\t(Mhash/second)')
        print()
    for kernel, run_times in sorted(run_results.items(), key=lambda k: k[0].SHORT_NAME):
        print('%7s:\t%.3f\t%.3f\t%.3f' % (
                    kernel.SHORT_NAME,
                    min(run_times) / 1000000,
                    (sum(run_times) / len(run_times)) / 1000000,
                    max(run_times)/1000000,
                ))

def cmd_listkernels(args):
    all_kernels = timelock.kernel.AlgorithmSHA256.KERNELS
    for kernel in sorted(all_kernels, key=lambda k: k.SHORT_NAME):
        print('%s - %s' % (kernel.SHORT_NAME, kernel.DESCRIPTION))

def cmd_create(args):
    delay = float(args.delay[:-1])
    delay_units = args.delay[-1].lower()
    if delay_units == 's':
        delay *= 1
    elif delay_units == 'm':
        delay *= 60
    elif delay_units == 'h':
        delay *= 60*60
    elif delay_units == 'd':
        delay *= 60*60*24
    elif delay_units == 'w':
        delay *= 60*60*24*7
    elif delay_units == 'y':
        delay *= 60*60*24*365
    else:
        logging.error("Unknown delay units '%s'; must be one of s/m/h/d/w/y" % delay_units)
        sys.exit(1)

    hash_rate = args.rate * 1000000

    per_chain_delay = delay / args.num_chains
    per_chain_n = int(hash_rate * per_chain_delay)

    tl = timelock.Timelock(args.num_chains, per_chain_n)

    pretty_json_dump(tl.to_json(), args.file)
    args.file.close()

def cmd_compute(args):
    tl = timelock.Timelock.from_json(json.loads(args.file.read()))

    if not (0 <= args.index < len(tl.chains)):
        logging.error('Index out of range; must be 0 <= idx < %d' % len(tl.chains))
        sys.exit(1)

    chain = tl.chains[args.index]

    start_time = time.monotonic()
    start_i = chain.i

    while not chain.unlock(1):

        hashes_per_sec = (chain.i - start_i) / (time.monotonic() - start_time)
        est_time_to_finish = (chain.n - chain.i) / hashes_per_sec

        logging.info('chain #%d: %ds elapsed, %ds to go at %.4f Mhash/s, i = %d, midstate = %s' % (
                     args.index,
                     time.monotonic() - start_time,
                     est_time_to_finish,
                     hashes_per_sec/1000000,
                     chain.i,
                     bitcoin.core.b2x(chain.midstate),
                     ))

    print('Done! Now run:')
    print('%s addmidstate %s %d %d %s' % (
        sys.argv[0],
        args.file.name,
        args.index,
        chain.i,
        bitcoin.core.b2x(chain.midstate)))

def cmd_lock(args):
    unlocked_tl = timelock.Timelock.from_json(json.loads(args.unlocked_file.read()))

    locked_tl = unlocked_tl.make_locked()

    pretty_json_dump(locked_tl.to_json(), args.locked_file)
    args.locked_file.close()

def cmd_unlock(args):
    tl = timelock.Timelock.from_json(json.loads(args.file.read()))

    start_time = time.monotonic()
    chain_idx = 0
    sum_hashes = 0

    while tl.secret is None:
        # ugh, this needs serious refactoring
        prev_chain_i = tl.chains[chain_idx].i

        if not tl.unlock(1):
            sum_hashes += tl.chains[chain_idx].i-prev_chain_i

            if tl.chains[chain_idx].secret is not None:
                logging.info('Done chain #%d' % chain_idx)
                chain_idx += 1

            else:
                hashes_per_sec = sum_hashes / (time.monotonic() - start_time)

                sum_hashes_left = ((tl.chains[chain_idx].n - tl.chains[chain_idx].i)
                                   + sum([chain.n for chain in tl.chains[chain_idx+1:]]))

                est_time_to_finish = sum_hashes_left / hashes_per_sec

                logging.info('chain #%d: %ds elapsed, %ds to go at %.4f Mhash/s' % (
                             chain_idx,
                             time.monotonic() - start_time,
                             est_time_to_finish,
                             hashes_per_sec/1000000,
                             ))

        args.file.seek(0)
        pretty_json_dump(tl.to_json(), args.file)
        args.file.truncate()

    print('Success! Secret is %s' % bitcoin.core.b2x(tl.secret))

def cmd_addsecret(args):
    tl = timelock.Timelock.from_json(json.loads(args.file.read()))

    # Try treating the secret as Base58 data first
    try:
        secret = bitcoin.base58.CBase58Data(args.secret)
    except bitcoin.base58.Base58Error:
        # Try treating it as hex data
        secret = bitcoin.core.x(args.secret)

    if tl.add_secret(secret):
        print('Success!')
    else:
        print('Failed!')

    args.file.seek(0)
    pretty_json_dump(tl.to_json(), args.file)
    args.file.truncate()
    args.file.close()

def cmd_addmidstate(args):
    tl = timelock.Timelock.from_json(json.loads(args.file.read()))

    tl.chains[args.chain_idx].i = args.i
    tl.chains[args.chain_idx].midstate = args.midstate

    args.file.seek(0)
    pretty_json_dump(tl.to_json(), args.file)
    args.file.truncate()
    args.file.close()


parser = argparse.ArgumentParser(description='Timelock encryption tool')
parser.add_argument("-q","--quiet",action="count",default=0,
                             help="Be more quiet.")
parser.add_argument("-v","--verbose",action="count",default=0,
                             help="Be more verbose. Both -v and -q may be used multiple times.")
parser.add_argument('--version', action='version', version=VERSION)

subparsers = parser.add_subparsers(title='Subcommands',
                                           description='All operations are done through subcommands:')

parser_listkernels = subparsers.add_parser('listkernels',
    help='List available kernels')
parser_listkernels.set_defaults(cmd_func=cmd_listkernels)

parser_benchmark = subparsers.add_parser('benchmark',
    help='Benchmark chain kernel(s)')
parser_benchmark.add_argument('-t', type=float, default=1.0, dest='runtime',
        help='Time to run each benchmark for')
parser_benchmark.add_argument('-n', type=int, default=5,
        help='# of runs per benchmark')
parser_benchmark.add_argument('kernel', nargs='*', metavar='KERNEL',
    help='Kernel to benchmark. May be specified multiple times; all available kernels if not specified.')
parser_benchmark.set_defaults(cmd_func=cmd_benchmark)

parser_create = subparsers.add_parser('create',
    help='Create a new timelock')
parser_create.add_argument('-n', type=int, default=10,
        dest='num_chains',
        help='# of parallel chains')
parser_create.add_argument('delay', type=str, metavar='DELAY[UNITS]',
        help='Desired unlocking delay')
parser_create.add_argument('rate', type=float, metavar='RATE',
        help='Estimated hashing rate of the unlocker in MHash/sec')
parser_create.add_argument('file', metavar='FILE', type=argparse.FileType('w'),
        help='Filename')
parser_create.set_defaults(cmd_func=cmd_create)

parser_compute = subparsers.add_parser('compute',
    help='Compute a timelock chain')
parser_compute.add_argument('file', metavar='FILE', type=argparse.FileType('r'))
parser_compute.add_argument('index', metavar='INDEX', type=int)
parser_compute.set_defaults(cmd_func=cmd_compute)

parser_lock = subparsers.add_parser('lock',
    help='Create a locked timelock from an unlocked timelock')
parser_lock.add_argument('unlocked_file', metavar='UNLOCKED', type=argparse.FileType('r'))
parser_lock.add_argument('locked_file', metavar='LOCKED', type=argparse.FileType('w'))
parser_lock.set_defaults(cmd_func=cmd_lock)

parser_unlock = subparsers.add_parser('unlock',
    help='Unlock a locked timelock')
parser_unlock.add_argument('file', metavar='FILE', type=argparse.FileType('r+'))
parser_unlock.set_defaults(cmd_func=cmd_unlock)

parser_addsecret = subparsers.add_parser('addsecret',
    help='Add a newly found secret to a timelock')
parser_addsecret.add_argument('file', metavar='FILE', type=argparse.FileType('r+'))
parser_addsecret.add_argument('secret', metavar='SECRET', type=str)
parser_addsecret.set_defaults(cmd_func=cmd_addsecret)

parser_addmidstate = subparsers.add_parser('addmidstate',
    help='Add a newly computed midstate to a timelock')
parser_addmidstate.add_argument('file', metavar='FILE', type=argparse.FileType('r+'))
parser_addmidstate.add_argument('chain_idx', metavar='CHAIN_IDX', type=int)
parser_addmidstate.add_argument('i', metavar='IDX', type=int)
parser_addmidstate.add_argument('midstate', metavar='MIDSTATE', type=bitcoin.core.x)
parser_addmidstate.set_defaults(cmd_func=cmd_addmidstate)

args = parser.parse_args()

args.verbosity = args.verbose - args.quiet

if args.verbosity == 0:
    logging.root.setLevel(logging.INFO)
elif args.verbosity > 1:
    logging.root.setLevel(logging.DEBUG)
elif args.verbosity == -1:
    logging.root.setLevel(logging.WARNING)
elif args.verbosity < -2:
    logging.root.setLevel(logging.ERROR)


if not hasattr(args, 'cmd_func'):
    parser.error('No command specified')

args.cmd_func(args)
