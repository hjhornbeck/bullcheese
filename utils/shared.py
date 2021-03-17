
from cryptography.hazmat.backends import default_backend as backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from secrets import randbits, token_bytes

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
    assert (key is None) or (len(key) == 32)

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
    assert (len(key) == 16) or (len(key) == 24) or (len(key) == 32)

    iv = token_bytes( len(key) )
    tag = hash_bytes( input )

    padder = padding.PKCS7( len(key)*8 ).padder()
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
    assert (len(key) == 16) or (len(key) == 24) or (len(key) == 32)

    if (len(input) % len(key)) != 0:    # only certain sizes are valid
        return None

    iv = input[:len(key)]

    cypher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend()).decryptor()
    padded = cypher.update(input[len(key):]) + cypher.finalize()
    del iv, cypher      # encourage GC

    padder = padding.PKCS7( len(key)*8 ).unpadder()
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

def generate_token( seed, cat, time, salt, key ):
    """Generate the token used to validate a run.

    PARAMETERS
    ==========
    seed: A bytes object representing the seed.
    cat: An int representing the category the seed was drawn from.
    time: The time the seed was drawn, in 1/16ths of a 
       second past epoch.
    salt: A bytes object containing this server's salt.
    key: A bytes object containing the encryption key.

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
    assert (len(key) == 16) or (len(key) == 24) or (len(key) == 32)

    # create the token's core
    core = seed + cat.to_bytes( 1, 'big' ) + time.to_bytes( 4, 'big' )

    # create the associated tag
    tag = hash_bytes( core, salt )

    # combine them into the appropriate length
    raw_token = core + tag[: len(key) - len(core)]

    # finally, encrypt and return
    cypher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=backend()).encryptor()
    token = cypher.update( raw_token ) + cypher.finalize()

    del core, tag, raw_token, cypher
    return token

def decrypt_token( seed, token, key, salt=None ):
    """Decrypt and validate the token. "Validate" means check
       that the provided seed matches the one inside the token, and
       the pseudo-nonce is as expected. The latter check can be
       disabled by not providing a salt.

    PARAMETERS
    ==========
    seed: A bytes object representing the seed.
    token: A bytes object of the token to validate.
    key: A bytes object containing the encryption key.
    salt: A bytes object containing this server's salt, or None if it
       isn't known.

    RETURN
    ======
    If the token is invalid, returns None. If it is valid, returns a 
      tuple consisting of (seed, cat, time), where
       seed is a bytes object representing the Minecraft seed,
       cat is an int representing the category the seed was drawn from,
       and time is the moment the seed was drawn, in 1/16th of a second past epoch.
    """
    assert type(seed) is bytes
    assert len(seed) == 8
    assert type(token) is bytes
    assert (len(token) == 16) or (len(token) == 24) or (len(token) == 32)
    assert (salt is None) or (type(salt) is bytes)
    assert (salt is None) or ((len(salt) >= 24) and (len(salt) <= 64))
    assert type(key) is bytes
    assert len(key) == len(token)

    # decrypt the token
    cypher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=backend()).decryptor()
    raw_token = cypher.update( token ) + cypher.finalize()
    del cypher

    # check that the seeds match
    if raw_token[:8] != seed:
        return None

    # check the pseudo-nonce (the "core" is 13 bytes long)
    if salt is not None:
        tag = hash_bytes( raw_token[:13], salt )
        if tag[: len(key) - 13] != raw_token[13:]:
            del tag
            return None

    return seed, raw_token[8], \
        int.from_bytes( raw_token[9:13], 'big' )
