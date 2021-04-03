#!/usr/bin/env python3

import argparse
from binascii import unhexlify

from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from datetime import datetime, timedelta, timezone

from secrets import randbits, token_bytes
from sys import exit

def hash_bytes( input, key=None ):
    """Apply SHA2-256. Optionally use HMAC.

    PARAMETERS
    ==========
    input: A bytes object to be encrypted and tagged.
    key: A bytes object containing the key, or None if no key is being
       used.

    RETURN
    ======
    A bytes object.
    """
    assert type(input) is bytes
    assert (key is None) or type(key) is bytes
    assert (key is None) or ((len(key) >= 24) and (len(key) <= 64))

    if key is None:
        tagger = hashes.Hash( hashes.SHA256(), backend=backend() )
    else:
        tagger = hmac.HMAC( key, hashes.SHA256(), backend=backend() )

    tagger.update( input )
    tag = tagger.finalize()
    del tagger

    return tag

def encrypt_bytes( input, key ):
    """Encrypt a byte sequence with AES. Length of key determines 
       the cypher chosen.

    PARAMETERS
    ==========
    input: A bytes object to be encrypted and tagged.
    key: A bytes object containing the key.

    RETURN
    ======
    A bytes object.
    """

    assert type(input) is bytes
    assert type(key) is bytes
    assert len(key) in [16, 24, 32]

    iv = token_bytes( 16 )  # AES always has block size 16
    tag = hash_bytes( input )

    padder = padding.PKCS7( 128 ).padder()
    padded = padder.update(input) + padder.update(tag) + \
            padder.finalize()

    cypher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend()).encryptor()
    encrypt = iv + cypher.update(padded) + cypher.finalize()

    del iv, tag, padder, padded, cypher # encourage GC
    return encrypt

def decrypt_bytes( input, key ):
    """Decrypt a byte sequence with AES, if possible.

    PARAMETERS
    ==========
    input: A bytes object to be decrypted and verified.
    key: A bytes object containing the key.

    RETURN
    ======
    If the input could be decrypted, return a bytes object.
      Otherwise, return None.
    """

    assert type(input) is bytes
    assert type(key) is bytes
    assert len(key) in [16, 24, 32]

    if (len(input) % len(key)) != 0:    # only certain sizes are valid
        return None

    iv = input[:16]

    cypher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend()).decryptor()
    padded = cypher.update(input[16:]) + cypher.finalize()
    del iv, cypher      # encourage GC

    padder = padding.PKCS7( 128 ).unpadder()
    try:
        tagged = padder.update(padded) + padder.finalize()
    except:
        del padder
        return None
    
    tag = hash_bytes( tagged[:-32] )
    if tag != tagged[-32:]:
        del tagged, tag
        return None

    else:
        del tag
        return tagged[:-32]

def generate_ticket( seed, cat, time, salt, key, blocks=2 ):
    """Generate the ticket used to validate a run.

    PARAMETERS
    ==========
    seed: A bytes object representing the seed.
    cat: An int representing the category the seed was drawn from.
    time: The time the seed was drawn, in 1/8ths of a 
       second past epoch.
    salt: A bytes object containing this server's salt.
    key: A bytes object containing the encryption key.
    blocks: How long the ticket is, in blocks of 16 bytes.
      Shorter tickets are easier to work with but also easier to
      forge. Only 1 and 2 are valid.

    RETURN
    ======
    A bytes object.
    """

    assert type(seed) is bytes
    assert len(seed) == 8
    assert type(cat) is int
    assert (cat >= 0) and (cat <= 255)
    assert type(time) is int
    assert (time >= 0) and (time <= 0xffffffff)
    assert type(salt) is bytes
    assert (len(salt) >= 24) and (len(salt) <= 64)
    assert type(key) is bytes
    assert len(key) in [16, 24, 32]
    assert blocks in [1,2]

    # create the ticket's core
    core = seed + cat.to_bytes( 1, 'big' ) + time.to_bytes( 4, 'big' )

    # create the associated tag
    tag = hash_bytes( core, salt )

    # combine them into the appropriate length
    raw_ticket = core + tag[: blocks*16 - len(core) ]

    # finally, encrypt and return
    cypher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=backend()).encryptor()
    ticket = cypher.update( raw_ticket ) + cypher.finalize()

    del core, tag, raw_ticket, cypher
    return ticket

def decrypt_ticket( seed, ticket, key, salt=None ):
    """Decrypt and validate the ticket. "Validate" means check
       that the provided seed matches the one inside the ticket, and
       the pseudo-nonce is as expected. The latter check can be
       disabled by not providing a salt.

    PARAMETERS
    ==========
    seed: A bytes object representing the seed.
    ticket: A bytes object of the ticket to validate.
    key: A bytes object containing the encryption key.
    salt: A bytes object containing this server's salt, or None if it
       isn't known.

    RETURN
    ======
    If the ticket is invalid, returns None. If it is valid, returns a 
      tuple consisting of (seed, cat, time), where
       seed is a bytes object representing the Minecraft seed,
       cat is an int representing the category the seed was drawn from,
       and time is the moment the seed was drawn, in 1/8th of a second past epoch.
    """
    assert type(seed) is bytes
    assert len(seed) == 8
    assert type(ticket) is bytes
    assert len(ticket) in [16, 32]
    assert (salt is None) or (type(salt) is bytes)
    assert (salt is None) or ((len(salt) >= 24) and (len(salt) <= 64))
    assert type(key) is bytes
    assert len(key) in [16, 24, 32]

    # decrypt the ticket
    cypher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=backend()).decryptor()
    raw_ticket = cypher.update( ticket ) + cypher.finalize()
    del cypher

    # check that the seeds match
    if raw_ticket[:8] != seed:
        return None

    # check the pseudo-nonce (the "core" is 13 bytes long)
    if salt is not None:
        tag = hash_bytes( raw_ticket[:13], salt )
        if tag[: len(ticket) - 13] != raw_ticket[13:]:
            del tag
            return None

    return seed, raw_ticket[8], \
        int.from_bytes( raw_ticket[9:13], 'big' )

def pretty_ticket( ticket, version=1 ):
    """Make the ticket look more appealing to human eyes.

    PARAMETERS
    ==========
    ticket: A bytes object representing the ticket.
    version: The version of formatting to use. Currently
       there's only 1.

    RETURN
    ======
    A string.
    """

    assert version == 1

    return (''.join( [f"{ticket[i*8:(i+1)*8].hex()}-" for i in range( len(ticket)>>3 )] ))[:-1]

def clean_ticket( ticket, version=1 ):
    """Make the ticket look more appealing to a computer.

    PARAMETERS
    ==========
    ticket: A string representing the ticket.
    version: The version of formatting to use. Currently
       there's only 1.
    

    RETURN
    ======
    A bytes object representing the ticket. If the input is invalid
      for the given format, a blank bytes object is returned.
    """

    assert version == 1

    for i,c in enumerate(ticket):
        if (i in [16,33,50]) != (c == '-'):
            return b''

    try:
        return unhexlify( ticket.replace("-","") )
    except:
        return b''

def encode_time( moment, epoch=datetime(2021,1,1,tzinfo=timezone(timedelta(0))) ):
    """Convert the given moment into 1/8th of a second since the epoch.

    PARAMETERS
    ==========
    moment: A datetime object to be converted. Must have a timezone associated with it!
    epoch: The epoch to use. Defaults to 2021/1/1 00:00:00 UTC.

    RETURN
    ======
    The appropriate integer.
    """

    assert type(moment) is datetime
    assert moment.tzinfo is not None
    assert type(epoch) is datetime
    assert epoch.tzinfo is not None

    delta = moment - epoch
    return int( delta.total_seconds()*8 + .5 )

def decode_time( moment, epoch=datetime(2021,1,1,tzinfo=timezone(timedelta(0))) ):
    """Convert the encoded time (1/8th of a second since epoch) into 
       a datetime object.

    PARAMETERS
    ==========
    moment: The integer representing a time to convert.
    epoch: The epoch to use. Defaults to 2021/1/1 00:00:00 UTC.

    RETURN
    ======
    A datetime object representing the given integer.
    """

    assert type(moment) is int
    assert moment >= 0
    assert type(epoch) is datetime
    assert epoch.tzinfo is not None

    return epoch + timedelta( milliseconds=moment*125 )

def unsigned_to_signed( integer, bits=64 ):
    """A quick helper to do what the tin says.

    PARAMETERS
    ==========
    integer: The integer to convert.
    bits: How many bits this number requires. Defaults to 8 bytes.

    RETURN
    ======
    A signed integer.
    """

    if integer < (1 << (bits-1)):
        return integer
    else:
        return integer - (1 << bits)
    

if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description='Generate or validate a FSG ticket. Primarily used for offline verification.')

   cmdline.add_argument( '--seed', metavar='INT', type=int, default=404, help='The seed to generate/validate.' )
   cmdline.add_argument( '--cat', metavar='INT', type=int, help='The category that seed falls into.' )
   cmdline.add_argument( '--time', metavar='INT', type=int, help='The time that seed becomes valid, in 1/8ths of a second since January 1st, 2021. Leave blank to use the current time.' )

   cmdline.add_argument( '--key', metavar='FILE/HEX', required=True, help='The secret key associated with this ticket. Ideally a filename, but a hex-encoded string also works.' )
   cmdline.add_argument( '--salt', metavar='FILE/HEX/STRING', help='The salt associated with this ticket. Optional for validation. Ideally a filename, but a hex-encoded string works, with a text string as a fallback.' )

   cmdline.add_argument( '--live_time', metavar='INT', type=int, default=7200, help='The number of seconds a ticket remains "live" after creation.' )
   cmdline.add_argument( '--dead_time', metavar='INT', type=int, default=14*86400, help='The number of seconds until a ticket transitions from "dead" to "invalid/expired".' )

   cmdline.add_argument( '--ticket', metavar='HEX', help='The ticket to be validated.' )
   cmdline.add_argument( '--blocks', metavar='SIZE', type=int, choices=[1,2], default=2, help='The number of blocks in the ticket. Only used for generation.' )

   args = cmdline.parse_args()

    
   # try to load that key, first as a file
   binary = None
   try:
       with open( args.key, 'rb' ) as f:
           binary = f.read()
   except:
       pass
        
   # did we read something?
   if binary is not None:

    # use the length to tell if its hex-encoded ...
    if len(binary) in [48, 64]:
        try:
            args.key = unhexlify( binary.decode('utf-8') )
        except:
            binary = None

    # ... or it is binary ...
    elif len(binary) in [16, 24]:
        args.key = binary

    # ... otherwise, decide based on if it decodes
    elif len(binary) == 32:
        try:
            binary = unhexlify( binary.decode('utf-8') )
        except:
            pass

        args.key = binary

   # if none of the above works, the key might be a hex string
   if (type(args.key) is str) and (len(args.key) in [32, 48, 64]):
        try:
            args.key = unhexlify( args.key )
        except:
            pass

   # still no key? give up
   if (type(args.key) is not bytes) or (len(args.key) not in [16, 24, 32]):
       print("ERROR: An invalid key was given! It must be a file or hex string, and either 16, 24, or 32 bytes long.")
       exit( 1 )

   # the salt's turn, if it was provided
   if args.salt is not None:
        binary = None
        try:
            with open( args.salt, 'rb' ) as f:
                binary = f.read()
        except:
            pass
        
        if binary is not None:

            # check if the length reveals it was hex encoded ...
            if (len(binary) > 64) and (len(binary) <= 128):
                try:
                    args.salt = unhexlify( binary.decode('utf-8') )
                except:
                    binary = None
                    
            # ... or it is raw bytes ...
            elif (len(binary) >= 24) and (len(binary) < 48):
                    args.salt = binary

            # ... or on whether or not it decodes
            elif (len(binary) >= 48) and (len(binary) <= 64):
                try:
                    binary = unhexlify( binary.decode('utf-8') )
                except:
                    pass

                args.salt = binary
                    
        # if none of the above works, the salt might be a hex string
        if (type(args.salt) is str) and \
                (len(args.salt) >= 48) and (len(args.salt) <= 128):
            try:
                args.salt = unhexlify( args.salt )
            except:
                pass

        # still nothing? Maybe it's a string
        if (type(args.salt) is str) and \
                (len(args.salt) >= 24) and (len(args.salt) <= 64):
            try:
                args.salt = args.salt.encode('utf-8')
            except:
                pass

        # if we haven't succeeded by now, there must have been an error
        if (type(args.salt) is not bytes) or \
                (len(args.salt) < 24) or (len(args.salt) > 64):
            print("ERROR: An invalid salt was given! It must be a file or string, between 24 and 64 bytes in size.")
            exit( 2 )

   # ensure the seed is the appropriate size
   if (args.seed >= (1 << 63)) or (args.seed < -(1 << 63)):
        print("ERROR: An invalid seed was given! It should be smaller.")
        exit( 3 )

   # convert the seed to unsigned bytes
   args.seed &= ((1 << 64) - 1)
   args.seed = args.seed.to_bytes( 8, 'big' )

   # fill in a time, if necessary
   if args.time is None:
       args.time = encode_time( datetime.now(timezone.utc) )

   # ticket given? Validate it
   if args.ticket is not None:

       # first off, convert to bytes
       try:
            args.ticket = clean_ticket( args.ticket )
       except:
            print("ERROR: An invalid ticket was given! It must be a hex string.")
            exit( 4 )

       # are we the proper size?
       if not (len(args.ticket) in [16,32]):
            print("ERROR: An invalid ticket was given! It must be either 16 or 32 bytes in size, and with the proper hyphenation.")
            exit( 5 )

       result = decrypt_ticket( args.seed, args.ticket, args.key, args.salt )

       # if it doesn't decrypt, we know we've got issues
       if result is None:
            print(f"The ticket is INVALID/EXPIRED!")
            print(f"  TICKET: {pretty_ticket( args.ticket )}")
            exit( 127 )

       # were we also given a category and time? Check them too
       seed, cat, time = result
       if (args.cat is not None) and (args.cat != cat):
            print(f"The ticket is INVALID/EXPIRED!")
            print(f"  TICKET: {pretty_ticket( args.ticket )}")
            exit( 127 )

       now = datetime.now(timezone.utc)          # must have timezone info
       creation = decode_time(time).astimezone() # decode and convert to local time

       seconds = int( (now - creation).total_seconds() + .5 )

       if seconds > args.dead_time:
            print(f"The ticket is INVALID/EXPIRED!")
            print(f"  TICKET: {pretty_ticket( args.ticket )}")
            exit( 127 )

       if seconds > args.live_time:
            print(f"The ticket is DEAD; if it was not submitted for verification while it was live, it is invalid.")
            print(f"    TIME: {creation.strftime('%Y/%m/%d %H:%M %Z')}")
       else:
            print(f"The ticket is LIVE, and could be a viable record if submitted for validation.")
            remaining = args.live_time - seconds
            print(f" EXPIRES: In {remaining // 3600} hours, {(remaining // 60)%60} minutes, and {remaining % 60} seconds.")

       print(f"  TICKET: {pretty_ticket( args.ticket )}")
       print(f"    SEED: {unsigned_to_signed(int.from_bytes( seed, 'big' ))}")
       print(f"     CAT: {cat}")
       if args.salt is None:
           print(" WARNING: No value for the salt was provided, so this could be a forged ticket.")

       exit( 0 )    # no need to indent the next section
   
   # otherwise, create it
   if args.salt is None:
        print("ERROR: A salt is necessary for generating a ticket!")
        exit( 6 )

   if args.cat is None:
        print("ERROR: A category is necessary for generating a ticket!")
        exit( 7 )

   ticket = pretty_ticket( generate_ticket( args.seed, args.cat, args.time, args.salt, args.key, args.blocks ) )
   print(f"Here is a ticket for seed {unsigned_to_signed(int.from_bytes( args.seed, 'big' ))}:")
   print(f" TICKET: {ticket}")

