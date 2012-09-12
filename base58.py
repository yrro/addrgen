_base58_codestring = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_base58_codestring_len = len (_base58_codestring)

def encode (x):
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


