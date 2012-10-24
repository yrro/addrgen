import ctypes
import ctypes.util

POINT_CONVERSION_COMPRESSED = 2
POINT_CONVERSION_UNCOMPRESSED = 4

NID_secp256k1 = 714

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl'))

ssl.ERR_load_crypto_strings.argtypes = ()
ssl.ERR_load_crypto_strings.restype = None

ssl.ERR_free_strings.argtypes = ()
ssl.ERR_free_strings.restype = None

ssl.ERR_get_error.argtypes = ()
ssl.ERR_get_error.restype = ctypes.c_ulong

ssl.ERR_error_string.argtypes = ctypes.c_ulong, ctypes.c_char_p
ssl.ERR_error_string.restype = ctypes.c_char_p

ssl.EC_KEY_new_by_curve_name.argtypes = ctypes.c_int,
def errcheck_EC_KEY_new_by_curve_name (result, func, arguments):
        import ctssl.err as err
        if result == 0:
                raise err.SSLError
        return ctypes.c_void_p (result)
ssl.EC_KEY_new_by_curve_name.errcheck = errcheck_EC_KEY_new_by_curve_name

ssl.EC_KEY_generate_key.argtypes = ctypes.c_void_p,
def errcheck_ECC_KEY_generate_key (result, func, arguments):
        import ctssl.err as err
        if result == 0:
                raise err.SSLError
        return result
ssl.EC_KEY_generate_key.errcheck = errcheck_ECC_KEY_generate_key

ssl.EC_KEY_get0_private_key.argtypes = ctypes.c_void_p,
def errcheck_EC_KEY_get0_private_key (result, func, arguments):
        import ctssl.err as err
        if result == 0:
                raise err.SSLError
        return ctypes.c_void_p (result)
ssl.EC_KEY_get0_private_key.errcheck = errcheck_EC_KEY_get0_private_key
