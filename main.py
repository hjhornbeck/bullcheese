#!/usr/bin/env python3

##### KEY VARIABLES

# how long is a ticket valid, in seconds?
LIVE_TIME = 2*60*60       # (two hours)

# how long after a ticket becomes invalid can we observe it?
DEAD_TIME = 14*24*60*60   # (two weeks)

# if someone constantly grabbed tickets, how long until they 
#  have a 50/50 chance of getting the seed they want?
LD50 = 31*86400           # (31 days)

# if a crooked validator tried to brute-force a valid ticket,
#  what are the maximal odds of success over DEAD_TIME seconds?
FORGE_SUCCESS = 0.001

# how long is the token, in 16-byte blocks? Can be 1, defaults to 2
BLOCKS = 2              # 2 is more annoying for end users, but vastly more secure

# how many seconds do we wait for a lock until giving up?
TIMEOUT = 15

# what directory are the seeds stored in?
SEED_DIR = "seeds"

# how about the HTML templates?
TEMPLATE_DIR = "templates"

# and where is our scratch hard drive space?
TMP_DIR = "/tmp"

# beyond this point, you shouldn't have to edit any variables manually


##### IMPORTS

from binascii import unhexlify

from datetime import datetime, timedelta, timezone

import errno

from flask import Flask, render_template, request
from filelock import Timeout, FileLock

from math import log, log1p

from os import getenv, strerror

from secrets import randbits, token_bytes

from time import sleep
from traceback import format_exc
from typing import Optional

from utils.fsg_seeds import load_seeds, parse_seeds

from utils.fsg_ticket import clean_ticket, decode_time, decrypt_bytes
from utils.fsg_ticket import decrypt_ticket, encode_time, encrypt_bytes
from utils.fsg_ticket import generate_ticket, hash_bytes, pretty_ticket
from utils.fsg_ticket import unsigned_to_signed


##### CLASSES

class Category:
    """An abstract representation of a seed category. The brains of the operation."""

    def __init__(self, num: int):
        """Create a Category, given the following arguments.

        PARAMETERS
        ==========
        num:             The category's number. Must be positive or zero.

        RAISES
        ======
        Various I/O exceptions, depending on whether files are where we expect or
           are writable.
        """
        global LD50, SALT, TIMEOUT, TMP_DIR

        assert num > 0      # unsigned only!

        self.numeric = num

        # load the seed file early so we can signal quickly
        result = load_seeds( self.seed_file() )
        if result is None:
            raise FileNotFoundError(errno.ENOENT, strerror(errno.ENOENT), self.seed_file())
        self.url, self.name, self.seeds = result

        # generate the filenames and locks 
        gen_lock_file = hash_bytes( f"{num:03d}.generate.lock", SALT ).hex()
        self.gen_lock = FileLock( f"{TMP_DIR}/{gen_lock_file}", timeout=TIMEOUT )
        self.gen_file = TMP_DIR + '/' + hash_bytes( f"{num:03d}.generate.file", SALT ).hex()

        ver_lock_file = hash_bytes( f"{num:03d}.verify.lock", SALT ).hex()
        self.ver_lock = FileLock( f"{TMP_DIR}/{ver_lock_file}", timeout=TIMEOUT )
        self.ver_file = TMP_DIR + '/' + hash_bytes( f"{num:03d}.verify.file", SALT ).hex()

        # it'd be wise to try writing to those files before going further
        now       = encode_time( datetime.now(timezone.utc) )
        bytecount = (now.bit_length() + 7) >> 3
        now_b     = encrypt_bytes( now.to_bytes( bytecount, 'big' ), PRIVATE_KEY )

        with open( self.gen_file, 'wb' ) as f:      # exceptions are passed up
            f.write( now_b )
        with open( self.ver_file, 'wb' ) as f:
            f.write( now_b )

        self.seed_count = len(seeds) >> 3
        self.seed_bits  = self.seed_count.bit_length()

        # calculate the generate interval from the number of seeds
        self.gen    = LD50 * log1p( -1/self.seed_count ) / log( .5 )


    def seed_file(self) -> str:
        """Return the file associated with this seed category."""
        global SEED_DIR

        return f"{SEED_DIR}/{self.numeric:03d}.seeds.gz"

    def generate(self) -> tuple[bytes,datetime.datetime,str]:
        """Generate a ticket. A smart wrapper around generate_ticket().

        RETURN
        ======
        A tuple of the form (seed, time, ticket), where seed is an int,
           time is a datetime object, and ticket a string.

        RAISES
        ======
        Timeout if the lock couldn't be acquired before TIMEOUT.
        Various I/O errors if the lock or last time generated couldn't
           be read.
        """
        global BLOCKS, PRIVATE_KEY, SALT, TICK

        last = encode_time( datetime.now(timezone.utc) )
        now  = None     # probably unnecessary

                    # acquire lock
        with self.gen_lock:

                    # read the last access time
            with open( self.gen_file, 'rb' ) as f:
                timing = decrypt_bytes( f.read(), PRIVATE_KEY )

            if timing is bytes:
                last = int.from_bytes( timing, 'big' )

            # too quick? sleep
            now   = datetime.now(timezone.utc)
            now_e = encode_time( now )
            delta = (now_e - last)*TICK

            if delta < self.gen:
                sleep( self.gen - delta )
                now = datetime.now(timezone.utc)

            # write the current time
            with open( self.gen_file, 'rb' ) as f:
                bytecount = (now.bit_length() + 7) >> 3
                f.write( encrypt_bytes( now.to_bytes(bytecount, 'big'), PRIVATE_KEY ) )

            # release lock

        # randomly pick seed via rejection sampling
        idx = randbits( self.seed_bits )
        while idx >= self.seed_count:
            idx = randbits( self.seed_bits )
        offset = idx << 3

        # pass to generate_ticket()
        ticket = generate_ticket( self.seeds[ offset:offset+8 ], self.numeric, \
                encode_time( now ), SALT, PRIVATE_KEY, BLOCKS )

        return self.seeds[ offset:offset+8 ], now, ticket

    def verify_throttle(self):
        """Handle the pause associated with verification. Allows external
           code to throttle when its known verification failed.
        """
        global PRIVATE_KEY, VERIFY_INT, TICK

                    # acquire lock
        with self.ver_lock:

                    # read the last access time
            with open( self.ver_file, 'rb' ) as f:
                timing = decrypt_bytes( f.read(), PRIVATE_KEY )

            if timing is bytes:
                last = int.from_bytes( timing, 'big' )
            else:
                last = None

            # too quick? sleep
            now   = datetime.now(timezone.utc)
            now_e = encode_time( now )
            if last is None:
                delta = 0
            else:
                delta = (now_e - last)*TICK

            if delta < VERIFY_INT:
                sleep( VERIFY_INT - delta )
                now = encode_time( datetime.now(timezone.utc) )

            # write the current time
            with open( self.gen_file, 'rb' ) as f:
                bytecount = (now.bit_length() + 7) >> 3
                f.write( encrypt_bytes( now.to_bytes(bytecount, 'big'), PRIVATE_KEY ) )

            # release lock

    def verify(self, seed: bytes, cat: int, time: int) -> bool:
        """Do the remaining verification of a ticket, things that 
           decrypt_ticket() cannot do.

        PARAMETERS
        ==========
        seed: The Minecraft seed, as a bytes object.
        cat: The category of the seed.
        time: 1/8ths of a second since the epoch.

        RETURN
        ======
        True if the ticket is fully verified, False otherwise.
        """
        
        # easy stuff first
        if cat != self.numeric:
            return False

        # finally, check the seed is in our archive
        # check two edge cases
        if (self.seeds[-8:] < seed) or (self.seeds[:8] > seed)
            return False

        # estimate where to find the seed
        estimate = int( int.from_bytes( seed, 'big' ) * self.seed_count / (1 << 64) )
        
        # ensure the estimate is a valid index
        if estimate >= self.seed_count:
            estimate = self.seed_count - 1
        elif estimate < 0:
            estimate = 0            # should never happen, but branch prediction makes this cheap

        # did we get lucky?
        offset = estimate << 3
        if self.seeds[ offset:offset+8 ] == seed:
            return True

        # too low? set that location to be left, scan for right
        if self.seeds[ offset:offset+8 ] < seed:
            left = estimate
            step = 1
            right = estimate + step

            while right < self.seed_count:
                offset = right << 3
                if self.seeds[ offset:offset+8 ] < seed:
                    step <<= 1
                    right += step
                elif self.seeds[ offset:offset+8 ] == seed:
                    return True
                else:
                    break

            if right >= self.seed_count:
                right = self.seed_count - 1

        # too high? set that location to be right, scan for left
        else:
            right = estimate
            step = 1
            left = estimate - step

            while left > 0:
                offset = left << 3
                if self.seeds[ offset:offset+8 ] > seed:
                    step <<= 1
                    left -= step
                elif self.seeds[ offset:offset+8 ] == seed:
                    return True
                else:
                    break

            if left < 0:
                left = 0

        # binary search, but only up to a limit
        while (right - left) > 8:          # TODO: what limit is optimal?

            middle = (left + right) >> 1
            offset = middle << 3

            if self.seeds[ offset:offset+8 ] == seed:
                return True
            elif self.seeds[ offset:offset+8 ] < seed:
                left = middle
            else:
                right = middle

        # within the limit? Linear scan
        for idx in range(left,right+1):
            offset = idx << 3
            if self.seeds[ offset:offset+8 ] == seed:
                return True

        # still not found? It's not on the list
        return False


##### METHODS

def get_key() -> tuple[bytes,bool]:
    """Retrieve the private key, encoded in hexadecimal. If not present, 
       pick a value randomly.

    RETURN
    ======
    A tuple of the form (key, was_generated).
    """

    try:
        temp = unhexlify( getenv("PRIVATE_KEY") )
        if len(temp) in [16,24,32]:
            return temp, False
    except:
        pass

    return token_bytes(32), True

def get_salt() -> tuple[bytes,bool]:
    """Retrieve the salt. If not present, pick one randomly.

    RETURN
    ======
    A tuple of the form (salt,was_RNG).
    """

    try:
        temp = unhexlify( getenv("SALT") )
        if (len(temp) >= 24) and (len(temp) <= 64):
            return temp, False
    except:
        pass

    return token_bytes(64), True

##### GENERATED/FIXED VARIABLES

assert BLOCKS in [1,2]

TICK = 0.125
INVTICK = 8

PRIVATE_KEY, RANDOM_KEY = get_key()
SALT, RANDOM_SALT       = get_salt()

url_map  = dict()        # for mapping between url names and category numbers
cat_map  = dict()        # for mapping between category numbers and classes
cat_list = list()        # (url,name) tuples for printing at the bottom of pages

seed_total = 0           # used for picking a random category, weighted by seed count
seed_bits  = 0
seed_list  = list()

validator = None         # use this Category to handle validation throttling

# the verify interval is identical for all categories
if BLOCKS == 2:
    VERIFY_INT = DEAD_TIME * log1p( -1/(1 << (19*8)) ) / log1p( -FORGE_SUCCESS )
else:
    VERIFY_INT = DEAD_TIME * log1p( -1/(1 << (3*8)) ) / log1p( -FORGE_SUCCESS )


##### MAIN

# init the web framework, so we can start logging
site = Flask(__name__)

site.logging.info(  "Initialized Flask." )
site.logging.info( f"LIVE_TIME = {LIVE_TIME}." )
site.logging.info( f"DEAD_TIME = {DEAD_TIME}." )
site.logging.info( f"LD50 = {LD50}." )
site.logging.info( f"FORGE_SUCCESS = {FORGE_SUCCESS}." )
site.logging.info( f"TIMEOUT = {TIMEOUT}." )
site.logging.info( f"BLOCKS = {BLOCKS}." )
site.logging.info( f"VERIFY_INT = {VERIFY_INT}s." )

if RANDOM_KEY:
    site.logging.info( "Using a randomly-generated PRIVATE_KEY." )
else:
    site.logging.info( f"PRIVATE_KEY is user-specified, of length {len(PRIVATE_KEY)}." )

if RANDOM_SALT:
    site.logging.info( "Using a randomly-generated SALT." )
else:
    site.logging.info( f"SALT is user-specified, of length {len(SALT)}." )

site.logging.info(  "Loading seeds." )

# load up and register the seeds
for idx in range(256):

    temp = None
    try:
        temp = Category(idx)
    except:
        continue        # no point carrying on

    cat_map[ idx ]      = temp
    url_map[ temp.url ] = idx
    cat_list.append( (temp.url,temp.name) )

    seed_list.append( (temp.seed_count + seed_total, idx) )
    seed_total += temp.seed_count

    if validator is None:
        validator = temp

site.logging.info( f"Loaded {seed_total} total seeds in {len(cat_map)} categories." )
seed_bits = seed_total.bit_length()


@site.route('/')
def index():
    # redirect to a random seed from a random category
    return create_ticket( None )

@site.route('/time')
def current_time():
    # display the server's current time
    return render_template( 'time.html', time=int(datetime.now(timezone.utc).timestamp()) )

@site.route('/ticket/', defaults={'cat': None})
@site.route('/ticket/<cat>')
def create_ticket(cat):

    if cat is not in cat_urls:
        # pick a random seed
        idx = randbits( seed_bits )
        while idx >= seed_total:
            idx = randbits( seed_bits )

        # figure out which category this seed is in
        if idx < seed_list[0]:
            cat = cat_list[0][0]
        else:
            left = 0
            right = len(seed_list)-1
            while (right - left) > 8:
                middle = (left + right) >> 1
                if seed_list[middle] > idx:
                    right = middle
                else:
                    left = middle
            for i in range(left,right+1):
                if idx < seed_list[i]:
                    cat = cat_list[i][0]
                    break
            else:
                cat = cat_list[right][0]

    num = cat_urls[cat]
    try:
        output = cat_map[num].generate()
    except:
        site.logging.error(f"Exception when generating a ticket: {format_exc()}" )
        return render_template( 'error.html' )

    seed, time, ticket = output
    seed_i = unsigned_to_signed( int.from_bytes(seed,'big') )
    ticket_p = pretty_ticket(ticket)

    site.logging.info(f"Created ticket {ticket_p} for category {num} and seed {seed_i}" )

    return render_template( 'generated.html', seed=seed_i, name=cat_map[num].name, time=time, \
            ticket=ticket_p, cats=cat_list )

@site.route('/validate/<seed>/<ticket>')
def validate(seed, ticket):
    global PRIVATE_KEY, SALT, TICK

    # throttling first
    validator.verify_throttle()
    now = datetime.now(timezone.utc)
    now_e = encode_time( now )

    # try to convert the seed from a string to an unsigned int
    try:
        seed_i = int(seed)
    except:
        site.logging.info(f"Asked to validate an invalid seed, ignoring." )
        return render_template( 'invalid_expired.html', cats=cat_list )

    if (seed_i > ((1 << 63) - 1)) or (seed_i < -(1 << 63)):
        site.logging.info(f"Asked to validate a seed that's too large or small, ignoring." )
        return render_template( 'invalid_expired.html', cats=cat_list )

    seed_b = (seed_i & ((1 << 64) - 1)).to_bytes( 8, 'big' )

    # time to check the ticket format
    ticket_b = clean_ticket( ticket )
    if len(ticket_b) not in [16,32]:
        site.logging.info(f"Asked to validate a ticket that's improperly formatted, ignoring." )
        return render_template( 'invalid_expired.html', cats=cat_list )

    # next up, decrypt the ticket
    results = decrypt_ticket( seed_b, ticket_b, PRIVATE_KEY, SALT )
    if results is None:
        site.logging.info(f"Asked to validate an invalid ticket for seed {seed_i}." )
        return render_template( 'invalid_expired.html', cats=cat_list )

    seed_n, cat, time = results
    if not cat_map[cat].verify( seed, cat, time ):
        site.logging.info(f"Secondary validation failed for seed {seed_i} and ticket {ticket}." )
        return render_template( 'invalid_expired.html', cats=cat_list )

    # ah, but how much time has elapsed?
    delta  = (now_e - time)*TICK
    time_d = decode_time( time )
    if delta < LIVE_TIME:
        return rended_template( 'live.html', seed=seed_i, time=int(LIVE_TIME - delta + .5), \
                name=cat_map[cat], cats=cat_list )

    elif delta < DEAD_TIME:
        dtime_str = (time_d + timedelta(seconds=LIVE_TIME)).strftime("%Y/%m/%d %H:%M")
        return render_template( 'dead.html', time=dtime_str, name=cat_map[cat], cats=cat_list )

    return render_template( 'invalid_expired.html', cats=cat_list )

site.run(host='0.0.0.0', port=8080)
