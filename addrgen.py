import argparse
import binascii
import hashlib
import multiprocessing

import base58
import ctssl

def wif (priv):
        '''
        Convert raw private key to base58-encoded wallet import format.

        >>> wif (binascii.unhexlify (b'338b7f9c13b44747fdef077898f688411693df40d5f6943ebba30917125934c9'))
        b'5JCzE8aEchKzGQThaYqKn5bcHvisWThwC2tU3eUB6VVAx1WV5fQ'
        '''
        result = b'\x80' + b'\x00' * (32 - len (priv)) + priv
        assert len (result) == 33
        h1 = hashlib.sha256 (result)
        h2 = hashlib.sha256 (h1.digest ())
        result += h2.digest ()[:4]
        return base58.encode (result)

def addr (pub):
        '''
        Convert raw public key to base58check-encoded address.

        >>> addr (binascii.unhexlify (b'04bbed292cf660fcd6fd29590ea53bbad38603a8b55d93806d12af56c994bae8d1df64d4b52607543c44031b26c401648928f748dd447c736b3c47f61f38477c28'))
        b'1Br8AVNn7XtvEBHc5hyaXsnPZFVAbLpNiL'
        '''
        assert len (pub) == 65 # pad?
        assert pub[0] == 4
        h3 = hashlib.sha256 (pub)
        h4 = hashlib.new ('ripemd160', h3.digest ())
        result = b'\x00' + h4.digest ()
        h5 = hashlib.sha256 (result)
        h6 = hashlib.sha256 (h5.digest ())
        result += h6.digest ()[:4]
        return base58.encode (result)

def generate (a):
        with ctssl.EC_KEY () as key:
                priv = key.priv ()
                pub = key.pub ()
                with print_lock:
                        print (wif (priv).decode ('ascii'), addr (pub).decode ('ascii'))
                        if a.raw:
                                print ('', binascii.hexlify (priv).decode ('ascii'), binascii.hexlify (pub).decode ('ascii'))

def main ():
        parser = argparse.ArgumentParser (description = 'Generate Bitcoin addresses.')
        parser.add_argument ('--count', '-c', help='Number of addresses to generate', action='store', default=1)
        parser.add_argument ('--raw', '-r', help='Display raw private/public key', action='store_true')
        a = parser.parse_args ()

        p = multiprocessing.Pool (processes=multiprocessing.cpu_count ())
        p.map (generate, [a] * int (a.count))

if __name__ == '__main__':
        print_lock = multiprocessing.Lock ()
        with ctssl.err.strings ():
                main ()
