

__all__ = ['EaxMode']

import struct
from binascii import unhexlify

from Crypto.Util.py3compat import byte_string, bord, _copy_bytes

from Crypto.Util._raw_api import is_buffer

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from Crypto.Hash import CMAC, BLAKE2s
from Crypto.Random import get_random_bytes


class EaxMode(object):
    """*EAX* mode.

    This is an Authenticated Encryption with Associated Data
    (`AEAD`_) mode. It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed,
    and it will still be subject to authentication.

    The decryption step tells the receiver if the message comes
    from a source that really knowns the secret key.
    Additionally, decryption detects if any part of the message -
    including the header - has been modified or corrupted.

    This mode requires a *nonce*.

    This mode is only available for ciphers that operate on 64 or
    128 bits blocks.

    There are no official standards defining EAX.
    The implementation is based on `a proposal`__ that
    was presented to NIST.

    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    .. __: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf

    :undocumented: __init__
    """

    def __init__(self, factory, key, nonce, mac_len, cipher_params):
        """EAX cipher mode"""

        self.block_size = factory.block_size
        """The block size of the underlying cipher, in bytes."""

        self.nonce = _copy_bytes(None, None, nonce)
        """The nonce originally used to create the object."""

        self._mac_len = mac_len
        self._mac_tag = None  # Cache for MAC tag

        # Allowed transitions after initialization
        self._next = ["update", "encrypt", "decrypt",
                      "digest", "verify"]

        # MAC tag length
        if not (2 <= self._mac_len <= self.block_size):
            raise ValueError("'mac_len' must be at least 2 and not larger than %d"
                             % self.block_size)

        # Nonce cannot be empty and must be a byte string
        if len(self.nonce) == 0:
            raise ValueError("Nonce cannot be empty in EAX mode")
        if not is_buffer(nonce):
            raise TypeError("nonce must be bytes, bytearray or memoryview")

        self._omac = [
                CMAC.new(key,
                         b'\x00' * (self.block_size - 1) + struct.pack('B', i),
                         ciphermod=factory,
                         cipher_params=cipher_params)
                for i in range(0, 3)
                ]

        # Compute MAC of nonce
        self._omac[0].update(self.nonce)
        self._signer = self._omac[1]

        # MAC of the nonce is also the initial counter for CTR encryption
        counter_int = bytes_to_long(self._omac[0].digest())
        self._cipher = factory.new(key,
                                   factory.MODE_CTR,
                                   initial_value=counter_int,
                                   nonce=b"",
                                   **cipher_params)

    def update(self, assoc_data):
        """Protect associated data

        If there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : bytes/bytearray/memoryview
            A piece of associated data. There are no restrictions on its size.
        """

        if "update" not in self._next:
            raise TypeError("update() can only be called"
                                " immediately after initialization")

        self._next = ["update", "encrypt", "decrypt",
                      "digest", "verify"]

        self._signer.update(assoc_data)
        return self

    def encrypt(self, plaintext, output=None):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        The data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : bytes/bytearray/memoryview
            The piece of data to encrypt.
            It can be of any length.
        :Keywords:
          output : bytearray/memoryview
            The location where the ciphertext must be written to.
            If ``None``, the ciphertext is returned.
        :Return:
          If ``output`` is ``None``, the ciphertext as ``bytes``.
          Otherwise, ``None``.
        """

        if "encrypt" not in self._next:
            raise TypeError("encrypt() can only be called after"
                            " initialization or an update()")
        self._next = ["encrypt", "digest"]
        ct = self._cipher.encrypt(plaintext, output=output)
        if output is None:
            self._omac[2].update(ct)
        else:
            self._omac[2].update(output)
        return ct

    def decrypt(self, ciphertext, output=None):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        The data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        This function does not remove any padding from the plaintext.

        :Parameters:
          ciphertext : bytes/bytearray/memoryview
            The piece of data to decrypt.
            It can be of any length.
        :Keywords:
          output : bytearray/memoryview
            The location where the plaintext must be written to.
            If ``None``, the plaintext is returned.
        :Return:
          If ``output`` is ``None``, the plaintext as ``bytes``.
          Otherwise, ``None``.
        """

        if "decrypt" not in self._next:
            raise TypeError("decrypt() can only be called"
                            " after initialization or an update()")
        self._next = ["decrypt", "verify"]
        self._omac[2].update(ciphertext)
        return self._cipher.decrypt(ciphertext, output=output)
from flask import Flask, render_template, request
import subprocess

'''
    a flask app to demo command injection vulnerability
'''

banner = ""
app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    '''
        this is the vulnerable endpoint
    '''
    return render_template('cmd.html')
    #out = subprocess.check_output(cmd, shell=True)

    #return out
@app.route('/execute_command',methods=['POST'])
def execute_command():
    '''
        this is the vulnerable endpoint
    '''
    out = "Bad command - only ping and dig are allowed"
    cmd = request.form['command']
    command_line = f"\nc:> dig {cmd}\n"
    if True:
        try:

            subprocess.call('cd runtime', shell=True)
            out = subprocess.check_output("dig "+str(cmd), shell=True, timeout=5)
        except:
            out = "Timeout reached!\n"
    # convert tabs to spaces
    buff = ''

    for b in out:
        if b == '\t':
            buff += '    '
        else:
            buff += chr(b)


    out = f"{banner}{command_line}{buff}"
    return out



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12345)

