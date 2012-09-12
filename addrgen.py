import argparse
import binascii
import hashlib

import base58
import ctssl

def wif (priv):
        result = b'\x80' + b'\x00' * (32 - len (priv)) + priv
        h1 = hashlib.sha256 (result)
        h2 = hashlib.sha256 (h1.digest ())
        result += h2.digest ()[:4]
        return base58.encode (result)

def addr (pub):
        assert len (pub) == 65 # pad?
        h3 = hashlib.sha256 (pub)
        h4 = hashlib.new ('ripemd160', h3.digest ())
        result = b'\x00' + h4.digest ()
        h5 = hashlib.sha256 (result)
        h6 = hashlib.sha256 (h5.digest ())
        result += h6.digest ()[:4]
        return base58.encode (result)

def main ():
        parser = argparse.ArgumentParser (description = 'Generate Bitcoin addresses.')
        parser.add_argument ('--count', '-c', help='Number of addresses to generate', action='store', default=1)
        parser.add_argument ('--raw', '-r', help='Display raw private/public key', action='store_true')
        a = parser.parse_args ()

        for x in range (int (a.count)):
                with ctssl.EC_KEY () as key:
                        priv = key.priv ()
                        pub = key.pub ()
                        print (wif (priv).decode ('ascii'), addr (pub).decode ('ascii'))
                        if a.raw:
                                print ('', binascii.hexlify (priv).decode ('ascii'), binascii.hexlify (pub).decode ('ascii'))

if __name__ == '__main__':
        main ()
