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

# beyond this point, you shouldn't have to edit any variables manually


##### IMPORTS

from binascii import unhexlify

from flask import Flask, render_template, request
from filelock import Timeout, FileLock

from os import getenv           # for loading secrets on repl.it

from secrets import token_bytes # secure RNG

from time import time
from typing import Optional

from utils.fsg_seeds import load_seeds, parse_seeds

from utils.fsg_ticket import clean_ticket, decode_time, decrypt_bytes
from utils.fsg_ticket import decrypt_ticket, encode_time, encrypt_bytes
from utils.fsg_ticket import generate_ticket, hash_bytes, pretty_ticket
from utils.fsg_ticket import unsigned_to_signed


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
