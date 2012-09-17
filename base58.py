_base58_codestring = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_base58_codestring_len = len (_base58_codestring)

def encode (x):
        '''
        Encode bytes into base58-encoded bytes.

        >>> import binascii
        >>> encode (b'\x30\x39')
        b'4fr'
        >>> encode (int (12345).to_bytes (2, 'big'))
        b'4fr'
        >>> encode (int (3471391110).to_bytes (4, 'big'))
        b'6Hknds'
        >>> encode (binascii.unhexlify (b'00'))
        b'1'
        >>> encode (binascii.unhexlify (b'0000'))
        b'11'
        >>> encode (binascii.unhexlify (b'01'))
        b'2'
        >>> encode (binascii.unhexlify (b'0198b9a10f'))
        b'BSxJKp'
        >>> encode (int (3429289555).to_bytes (4, 'big'))
        b'6E31Jz'
        '''
        q = int.from_bytes (x, 'big')
        result = bytearray ()
        while q > 0:
                q, r = divmod (q, _base58_codestring_len)
                result.append (_base58_codestring[r])
        for c in x:
                if c == 0:
                        result.append (_base58_codestring[0])
                else:
                        break
        result.reverse ()
        return bytes (result)


