import ctypes

import ctssl.err as err
import ctssl.detail as detail

class EC_KEY:
        def __init__ (self):
                pass

        def __enter__ (self):
                self.k = detail.ssl.EC_KEY_new_by_curve_name (detail.NID_secp256k1)
                detail.ssl.EC_KEY_generate_key (self.k)
                return self

        def __exit__ (self, *exc_info):
                detail.ssl.EC_KEY_free (self.k)

        def pub (self):
                size = detail.ssl.i2o_ECPublicKey (self.k, 0)
                if size == 0:
                        raise err.SSLError
                b = ctypes.create_string_buffer (size)
                detail.ssl.i2o_ECPublicKey (self.k, ctypes.byref (ctypes.pointer (b)))
                return b.raw

        def priv (self):
                pk = detail.ssl.EC_KEY_get0_private_key (self.k)
                size = BN_num_bytes (pk)
                if size == 0:
                        raise err.SSLError
                b = ctypes.create_string_buffer (size)
                detail.ssl.BN_bn2bin (pk, ctypes.pointer (b))
                return b.raw

def BN_num_bytes (bn):
        return (detail.ssl.BN_num_bits (bn) + 7) // 8
