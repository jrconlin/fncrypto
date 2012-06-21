# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Note: pycryptopp does not install properly. The actual repository is under
    ./src/pycryptopp/src/pycryptopp. This can be fixed by adding a symlink.
    ln -s ./src/pycryptopp/src/pycryptopp ./src/pycryptopp/pycryptopp

"""
import base64
import os
import hashlib
import sys

from M2Crypto import EVP
import cStringIO

import binascii


class FNCryptoException (Exception):
    pass


class FNCrypto (object):

    # While not strictly necessary, you may want to change this value. This
    # will alter the HMAC_INPUT seed value.
    appName = 'fnCrypto'
    HMAC_INPUT = appName + "-AES_256_ECB-HMAC256"
    bitSize = 256
    keyBundle = None

    def __init__(self, storage=None):
        """ initialize the crypto functions if need be.

        @arg storage "dict" like storage.
        """
        #aes.start_up_self_test()
        if storage is not None:
            self.storage = storage
        else:
            sys.stderr.write("WARNING: no storage defined\n")
            self.storage = {}
        self.syncKey = base64.b32encode(
                os.urandom(self.bitSize / 8)).lower().replace('l',
                        '8').replace('o', '9')

    def getUserToken(self, uid=0):
        """ Get information associated with the user's ID.
            AKA, their token.
        """
        token = self.storage.get(uid, {'uid': uid,
            'url': 'http://localhost'})
        #fetch user token from tokenServer:/1.0/fncrypto/1.0
        return token

    def setUserToken(self, uid=0, info=None):
        info.update({'uid': uid})
        self.storage[uid] = info
        return self.storage[uid]

    def generateKeyBundle(self, uid=None):
        """NOTE: The key bundle *should* come from the client. Any
        key bundle generated here will not work on the client.

        This is included for both example and testing.
        """
        #logger.warn("Using internal key bundle gnerator")
        if uid is None:
            uid = self.getUserToken().get('uid')
        if not hasattr(self, 'userToken'):
            self.userToken = self.getUserToken(uid)
        self.info = '%s%s' % (self.HMAC_INPUT,
                self.userToken.get('uid'))
        self.encryptionKey = hashlib.sha256('%s%s\01' % (
                self.syncKey, self.info)).hexdigest()
        # The url *should* come from the client.
        self.keyBundle = {'encryptionKey': self.encryptionKey,
            'hmac': hashlib.sha256('%s%s\02' % (self.encryptionKey,
                self.info)).hexdigest(),
            'url': 'http://localhost'}
        #self.storage(uid, 'keyBundle', self.keyBundle)
        self.setUserToken(uid, self.keyBundle)
        return self.keyBundle

    def getKeyBundle(self, uid):
        if self.keyBundle is not None:
            return self.keyBundle
        #fetch the keyBundle from "storage"
        if uid in self.storage:
            return self.storage[uid]
        else:
            return self.generateKeyBundle(uid)

    def encrypt(self, plaintext, keyBundle):
        """
        encrypt a block of plaintext using 256bit AES with ecb.

        @param plaintext plaintext string to encrypt
        @param keyBundle stored key information provided from the client.

        @return an encrypted message block
        """
        ## The initialization vector,
        iv = os.urandom(16)
        # This will need to be sent to the client to decrypt.
        result = {'iv': binascii.b2a_base64(iv)}
        # encode the text:
        # in long form:
        # key = sha256 (encryptionKey in hex + iv)
        # cipherText = aes(key=key).process(plainText)
        # result['cipherText'] = base64 encoded cipherText
        keyCore = '%s%s' % (
                keyBundle['encryptionKey'].decode('hex'), iv)
        # use a hex encoding to match the JS client library limitation
        key = hashlib.sha256(keyCore.encode('hex')).digest()
        aes = EVP.Cipher(alg='aes_256_ecb',
                    key=key,
                    iv=iv,
                    op=1)  # encode=1, decode=0
        inBuf = cStringIO.StringIO(plaintext)
        outBuff = cStringIO.StringIO()
        while 1:
            buf = inBuf.read()
            if not buf:
                break
            outBuff.write(aes.update(buf))
        outBuff.write(aes.final())
        cblock = outBuff.getvalue()
        """
        sys.stderr.write("     iv:%s\n    key: %s\n  Block: %s\n" %
                (binascii.b2a_hex(iv),
                    binascii.b2a_hex(key),
                    binascii.b2a_hex(cblock)));
        """
        result['cipherText'] = binascii.b2a_base64(cblock).replace('\n', '')
        # Generate the hmac as a hex version of the sha256 of the keyBundle's
        # HMAC, the b64 encoded cipherText we just generated, and the
        # keyBundle's source URL.
        result['hmac'] = hashlib.sha256("%s%s%s" % (keyBundle['hmac'],
            result['cipherText'], keyBundle['url'])).hexdigest()
        # And return that base structure. This is the "cryptoBlock"
        # inclusion to the POST data sent to the Notification URL.
        return result

    def decrypt(self, cryptBlock, keyBundle):
        """
        decrypt an encrypted message block

        @param cryptBlock dict containing encrypted variables
        @param keyBundle stored key information provided from the client

        @return the cleartext content of the message.
        """
        localHmac = hashlib.sha256('%s%s%s' % (keyBundle['hmac'],
            cryptBlock['cipherText'], keyBundle['url'])).hexdigest()
        if localHmac != cryptBlock['hmac']:
            raise FNCryptoException('Invalid HMAC')
        iv = binascii.a2b_base64(cryptBlock['iv'])
        keyCore = '%s%s' % (keyBundle['encryptionKey'].decode('hex'),
                iv)
        key = hashlib.sha256(keyCore.encode('hex')).digest()
        aes = EVP.Cipher(alg='aes_256_ecb',
                key=key,
                iv=iv,
                op=0)  # encode=1, decode=0
        inBuf = cStringIO.StringIO(
                binascii.a2b_base64(cryptBlock['cipherText']))
        outBuff = cStringIO.StringIO()
        while 1:
            buf = inBuf.read()
            if not buf:
                break
            outBuff.write(aes.update(buf))
        outBuff.write(aes.final())
        clearText = outBuff.getvalue()
        #clearText = aes.AES(key=key).process(
        #        binascii.a2b_base64(cryptBlock['cipherText']))
        return clearText


if __name__ == '__main__':
    crypto = FNCrypto()
    testPhrase = 'This is a test of the emergency broadcasting network.'
    # The key bundle normally comes from the client.
    # Generate a fake one for this test
    kb = crypto.generateKeyBundle()
    block = crypto.encrypt(testPhrase, kb)
    response = crypto.decrypt(block, kb)
    assert(response == testPhrase)
    print 'ok'
