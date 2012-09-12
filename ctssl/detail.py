import ctypes

NID_secp256k1 = 714

ssl = ctypes.cdll.LoadLibrary ('libssl.so.1.0.0')

ssl.EC_KEY_new_by_curve_name.argtypes = ctypes.c_int,
def errcheck_EC_KEY_new_by_curve_name (result, func, arguments):
        if result == 0:
                raise SSLError ('EC_KEY not created')
        return ctypes.c_void_p (result)
ssl.EC_KEY_new_by_curve_name.errcheck = errcheck_EC_KEY_new_by_curve_name

ssl.EC_KEY_generate_key.argtypes = ctypes.c_void_p,
def errcheck_ECC_KEY_generate_key (result, func, arguments):
        if result == 0:
                raise SSLError ('EC_KEY not generated')
        return result
ssl.EC_KEY_generate_key.errcheck = errcheck_ECC_KEY_generate_key

ssl.EC_KEY_get0_private_key.argtypes = ctypes.c_void_p,
def errcheck_EC_KEY_get0_private_key (result, func, arguments):
        if result == 0:
                raise SSLError ('BIGNUM not returned')
        return ctypes.c_void_p (result)
ssl.EC_KEY_get0_private_key.errcheck = errcheck_EC_KEY_get0_private_key


