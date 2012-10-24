import argparse
import binascii
import hashlib
import multiprocessing

import base58
import ctssl

def wif (priv, compressed, testnet=False):
        '''
        Convert raw private key to base58-encoded wallet import format.

        >>> wif (binascii.unhexlify (b'1111111111111111111111111111111111111111111111111111111111111111'), False)
        b'5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh'
        >>> wif (binascii.unhexlify (b'1111111111111111111111111111111111111111111111111111111111111111'), True)
        b'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp'
        >>> wif (binascii.unhexlify (b'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), False)
        b'5KVzsHJiUxgvBBgtVS7qBTbbYZpwWM4WQNCCyNSiuFCJzYMxg8H'
        >>> wif (binascii.unhexlify (b'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), True)
        b'L4ezQvyC6QoBhxB4GVs9fAPhUKtbaXYUn8YTqoeXwbevQq4U92vN'
        >>> wif (binascii.unhexlify (b'47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012'), False)
        b'5JMys7YfK72cRVTrbwkq5paxU7vgkMypB55KyXEtN5uSnjV7K8Y'
        >>> wif (binascii.unhexlify (b'47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012'), True)
        b'KydbzBtk6uc7M6dXwEgTEH2sphZxSPbmDSz6kUUHi4eUpSQuhEbq'
        '''
        result = (b'\x80' if not testnet else b'\xef') + (b'\x00' * (32 - len (priv)) + priv)
        assert len (result) == 33
        if compressed:
                result += b'\x01'
        h1 = hashlib.sha256 (result)
        h2 = hashlib.sha256 (h1.digest ())
        result += h2.digest ()[:4]
        return base58.encode (result)

def addr (pub, testnet=False):
        '''
        Convert raw public key to base58check-encoded address.

        >>> addr (binascii.unhexlify (b'044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1'))
        b'1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a'
        >>> addr (binascii.unhexlify (b'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'))
        b'1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9'
        >>> addr (binascii.unhexlify (b'04ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bdedc416f5cefc1db0625cd0c75de8192d2b592d7e3b00bcfb4a0e860d880fd1fc'))
        b'1JyMKvPHkrCQd8jQrqTR1rBsAd1VpRhTiE'
        >>> addr (binascii.unhexlify (b'02ed83704c95d829046f1ac27806211132102c34e9ac7ffa1b71110658e5b9d1bd'))
        b'1NKRhS7iYUGTaAfaR5z8BueAJesqaTyc4a'
        >>> addr (binascii.unhexlify (b'042596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3ed0a9004acf927666eee18b7f5e8ad72ff100a3bb710a577256fd7ec81eb1cb3'))
        b'1PM35qz2uwCDzcUJtiqDSudAaaLrWRw41L'
        >>> addr (binascii.unhexlify (b'032596957532fc37e40486b910802ff45eeaa924548c0e1c080ef804e523ec3ed3'))
        b'19ck9VKC6KjGxR9LJg4DNMRc45qFrJguvV'
        '''
        if pub[0] == 4:
                assert len (pub) == 65
        elif pub[0] == 2 or pub[0] == 3:
                assert len (pub) == 33
        else:
                assert False, 'Unknown public key format: {}'.format (pub[0])
        h3 = hashlib.sha256 (pub)
        h4 = hashlib.new ('ripemd160', h3.digest ())
        result = (b'\x00' if not testnet else b'\x6f') + h4.digest ()
        h5 = hashlib.sha256 (result)
        h6 = hashlib.sha256 (h5.digest ())
        result += h6.digest ()[:4]
        return base58.encode (result)

def generate (a):
        with ctssl.EC_KEY (compressed=not a.uncompressed) as key:
                priv = key.priv ()
                pub = key.pub ()
                with print_lock:
                        print (wif (priv, key.compressed, testnet=a.testnet).decode ('ascii'), addr (pub, testnet=a.testnet).decode ('ascii'))
                        if a.raw:
                                print ('', binascii.hexlify (priv).decode ('ascii'), binascii.hexlify (pub).decode ('ascii'))

def main ():
        parser = argparse.ArgumentParser (description = 'Generate Bitcoin addresses.')
        parser.add_argument ('--number', '-n', help='Number of addresses to generate', action='store', default=1)
        parser.add_argument ('--uncompressed', '-u', help='Use uncompressed format', action='store_true')
        parser.add_argument ('--raw', '-r', help='Display raw private/public key', action='store_true')
        parser.add_argument ('--testnet', '-t', help='Generate testnet address', action='store_true')
        a = parser.parse_args ()

        p = multiprocessing.Pool (processes=multiprocessing.cpu_count ())
        p.map (generate, [a] * int (a.number))

if __name__ == '__main__':
        print_lock = multiprocessing.Lock ()
        with ctssl.err.strings ():
                main ()
