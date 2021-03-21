#!/usr/bin/env python3

import argparse
import gzip
from io import BytesIO
from sys import exit

def parse_seeds( file ):
    """Parse the seed information from a file stream.

    PARAMETERS
    ==========
    file: A file-like object to read from.

    RETURN
    ======
    A tuple of the form (url, name, seeds), where:
       url is a string containing the url these seeds can be reached from,
       name is a long-form description of these seeds,
       and seeds is a bytes object containing the seeds. On failure, return
       None.
    """
    
    # format: url, name, seeds. url and name are preceeded by how long they are.
    len_url = int.from_bytes( file.read(1), 'big' )
    if len_url == 0:
        return None
    try:
        url = file.read(len_url).decode('utf-8')
    except:
        return None

    len_name = int.from_bytes( file.read(2), 'big' )
    if len_name == 0:
        return None
    try:
        name = file.read(len_name).decode('utf-8')
    except:
        return None

    return (url, name, file.read())

def load_seeds( filename, sort=True ):
    """Load up the seeds contained in the given file. Optionally sorts them.

    PARAMETERS
    ==========
    filename: A string containing the obvious.
    sort: A boolean on whether or not to sort the seeds.

    RETURN
    ======
    A tuple of the form (url, name, seeds), where:
       url is a string containing the url these seeds can be reached from,
       name is a long-form description of these seeds,
       and seeds is a bytes object containing the seeds. On failure, return
       None.
    """

    assert type(filename) is str
    assert type(sort) is bool

    try:
        if filename[-3:] == '.gz':
            f = gzip.open( filename, 'rb' )
        else:
            f = open( filename, 'rb' )
    except:
        return None

    output = parse_seeds( f )
    f.close()

    if (type(output) is not tuple) or (len(output) != 3):
        return None

    url, name, seeds = output
    if sort:

        array = [seeds[ i : i+8 ] for i in range(0, len(seeds), 8)]
        array.sort()            # better to do this in-place than call sorted
        seeds = b''.join( array )
        del array

    return url, name, seeds

def read_TSVs( files, sort=True ):
    """Given a list of filenames, turn them into an array of seeds. Each seed is
       a bytes object in big-endian format.

    PARAMETERS
    ==========
    files: A list of strings, representing files to read.
    sort: Should the packed seeds be sorted?

    RETURN
    ======
    A bytes object readable by parse_seeds()
    """

    assert type(files) in [tuple, list]
    assert type(sort) is bool

    seeds = list()
    for filename in files:
        # open depending on gzip or bare
        try:
            if filename[-3:] == '.gz':
                f = gzip.open( filename, 'rb' )
            else:
                f = open( filename, 'rb' )
        except:
            continue    # just move on if one fails

        for line in f:
            # read in seeds
            try:
                seed = int(line)
            except:
                continue

            # convert to unsigned and pack
            seed &= ((1 << 64) - 1)
            seeds.append( seed.to_bytes( 8, 'big' )

    if sort:
        seeds.sort()

    return seeds

def pack_seeds( url, name, seeds, sort=True ):
    """Create a seed file.

    PARAMETERS
    ==========
    url: A str containing the url these seeds can be reached from.
    name: A str containing the long-form description of these seeds.
    seeds: A list of bytes objects, as output by read_TSVs().
    sort: Should the packed seeds be sorted?

    RETURN
    ======
    A bytes object readable by parse_seeds()
    """

    assert type(url) is str
    assert type(name) is str
    assert type(seeds) in [tuple, list]
    assert type(sort) is bool

    url_enc = url.encode('utf-8')
    name_enc = name.encode('utf-8')

    assert len(url_enc) < 256
    assert len(name_enc) < (1 << 16)

    # handle the header first
    header = [len(url_enc).to_bytes( 1, 'big' ),  url_enc,
              len(name_enc).to_bytes( 2, 'big' ), name_enc]

    if sort:
        return b''.join( header + sorted(seeds) )

    return b''.join( header + seeds )


##### MAIN

if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description='Pack or unpack the seed files used by the FSG code.')

   cmdline.add_argument( '--output', metavar='FILENAME', type=argparse.FileType('wb', 0), help='Where to place the output.' )
   cmdline.add_argument( '--input', metavar='FILENAME', type=argparse.FileType('rb', 0), help='Read packed seeds from this file.' )
   cmdline.add_argument( '--url', metavar='STRING', type=str, help='The URL-friendly name associated with the output file.' )
   cmdline.add_argument( '--name', metavar='STRING', type=str, help='The human-friendly name associated with the output file.' )
   cmdline.add_argument( 'seeds', metavar='TSV', nargs='*', type=str, help='Read seeds from these TSV files.' )

   args = cmdline.parse_args()

   # handle the packed input first
   unpacked = None
   if args.input:
        unpacked = load_seeds( args.input.name )      # cheat and rely on argparse for file detection
        if unpacked is None:
            print( f"ERROR: Could not read the input seed file '{args.input.name}'. Double-check it exists and has the right format." )
            exit( 1 )

   # next, the TSVs
   seeds = list()
   if args.seeds:
        
        # no URL? try poaching it from the packed seed file
        if (args.url is None) and (unpacked is not None) and (len(unpacked) == 3):
            args.url = unpacked[0]

        # complain if we weren't given a URL even though we're asked to create a packed file
        if (args.url is None) and args.output:
            print( f"ERROR: When writing to a file, a URL is mandatory. Please supply one on the command line." )
            exit( 2 )

        # repeat the above for the name
        if (args.name is None) and (unpacked is not None) and (len(unpacked) == 3):
            args.url = unpacked[1]

        if (args.name is None) and args.output:
            print( f"ERROR: When writing to a file, a name is mandatory. Please supply one on the command line." )
            exit( 3 )
            
        # now start reading in the TSVs
        seeds = read_TSVs( args.seeds )

    # finally, are we writing to a file or printing?
    if args.output:

        # merge the read file + TSVs, as applicable, and write them out
    else:

        # otherwise, do a mass print of all the seeds (with embedded URL and name info, if provided)
