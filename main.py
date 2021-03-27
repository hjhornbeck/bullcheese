#!/usr/bin/env python3

##### KEY VARIABLES

# how long is a ticket valid, in seconds?
LIVE_TIME = 2*60*60       # (two hours)

# how long after a ticket becomes invalid can we observe it?
DEAD_TIME = 14*24*60*60   # (two weeks)

# if someone constantly grabbed tickets, how long until they 
#  have a 50/50 chance of getting the seed they want?
LD50 = 86400              # (one week)

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

import errno

from flask import Flask, render_template, request
from filelock import Timeout, FileLock

from math import ceil, log2

from os import getenv, strerror

from secrets import randbits, token_bytes

from time import time
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
        """
        global FORGE_SUCCESS, LD50, SALT, TIMEOUT, TMP_DIR

        assert num > 0      # unsigned only!

        self.numeric = num

        # load the seed file early so we can signal quickly
        self.url, self.name, self.seeds = load_seeds( self.seed_file() )
        if self.seeds is None:
            raise FileNotFoundError(errno.ENOENT, strerror(errno.ENOENT), self.seed_file())

        self.seed_count = len(seeds) >> 3
        self.seed_bits  = int(ceil(log2( self.seed_count )))

        # calculate the generate and verify interval from the number of seeds
        self.gen    = gen_interval
        self.verify = verify_interval

        # generate the filenames and locks 
        gen_lock_file = hash_bytes( f"{num:03d}.generate.lock", SALT ).hex()
        self.gen_lock = FileLock( f"{TMP_DIR}/{gen_lock_file}", timeout=TIMEOUT )
        self.gen_file = TMP_DIR + '/' + hash_bytes( f"{num:03d}.generate.file", SALT ).hex()

        ver_lock_file = hash_bytes( f"{num:03d}.verify.lock", SALT ).hex()
        self.ver_lock = FileLock( f"{TMP_DIR}/{ver_lock_file}", timeout=TIMEOUT )
        self.ver_file = TMP_DIR + '/' + hash_bytes( f"{num:03d}.verify.file", SALT ).hex()

    def seed_file(self):
        """Return the file associated with this seed category."""
        global SEED_DIR

        return f"{SEED_DIR}/{self.numeric:03d}.seeds.gz"

    def generate(self):
        """Generate a ticket. A smart wrapper around generate_ticket().

        RETURN
        ======
        A tuple of the form (seed, time, ticket), where seed is an int,
           time is a datetime object, and ticket a string.
        """
        global BLOCKS, PRIVATE_KEY, SALT

        # acquire lock
        # read last access time
        # too quick? sleep
        # write current time
        # release lock
        # randomly pick seed
        # pass to generate_ticket()
        # return

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

##### GENERATED VARIABLES

PRIVATE_KEY, RANDOM_KEY = get_key()
SALT, RANDOM_SALT       = get_salt()

url_map = dict()        # for mapping between url names and category numbers
cat_map = dict()        # for mapping between category numbers and classes

##### MAIN

# for each potential category of seeds,
#  load it up and register it

# init more variables


web_site = Flask(__name__)

@web_site.route('/')
def index():
    # redirect to one of the loaded seeds
    return create_ticket( None )

@web_site.route('/time')
def current_time():
    # display the server's current time
    return render_template( 'time.html', time=int(time()) )

@web_site.route('/ticket/', defaults={'cat': None})
@web_site.route('/ticket/<cat>')
def create_ticket(cat):
    if cat is None:
        # pick a random category from cat_urls

    if cat in cat_urls:
        # display the ticket for that 
        app.logger.info('%s failed to log in', user.username)

	if not username:
		username = request.args.get('username')

	if not username:
		return 'Sorry error something, malformed request.'

	return render_template('personal_user.html', user=username)

@web_site.route('/validate/<seed>/<ticket>')
def validate(seed, ticket):
    # validate the ticket
    return render_template('page.html', code=choice(number_list))

web_site.run(host='0.0.0.0', port=8080)
