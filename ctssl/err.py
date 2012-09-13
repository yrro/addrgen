import ctssl.detail as detail

class SSLError (Exception):
        def __init__ (self, msg=None):
                if msg is None:
                        msg = detail.ssl.ERR_error_string (detail.ssl.ERR_get_error (), None).decode ('ascii')
                Exception.__init__ (self, msg)

class strings:
        def __enter__ (self):
                detail.ssl.ERR_load_crypto_strings ()
        def __exit__ (self, *exc_info):
                detail.ssl.ERR_free_strings ()
