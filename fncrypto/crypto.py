"""Note: pycryptopp does not install properly. The actual repository is under
    ./src/pycryptopp/src/pycryptopp. This can be fixed by adding a symlink.
    ln -s ./src/pycryptopp/src/pycryptopp ./src/pycryptopp/pycryptopp

    Investigating other options.
"""
import base64
import os
import hashlib

from pycryptopp.cipher import aes

class CryptoException (Exception):
    pass


class Crypto (object):

    defaults = {'v': 1,
            'iter': 1000,
            'ks': 256,
            'ts': 64,
            'mode': 'ccm',
            'adata': '',
            'cipher': 'aes'}

    appName = 'fnCrypto'
    HMAC_INPUT = appName + "-AES_256_CBC-HMAC256"
    bitSize = 256
    keyBundle = None

    def __init__(self, storage=None):
        aes.start_up_self_test()
        if storage is not None:
            self.storage = storage
        else:
            print "no storage defined"
            self.storage = {};
        self.syncKey = base64.b32encode(
                os.urandom(self.bitSize / 8)).lower().replace('l', 
                        '8').replace('o', '9')

    def getUserToken(self, uid=0):
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
        encrypt a block of plaintext.

        @param plaintext plaintext string to encrypt
        @param keyBundle stored key information provided from the client.

        @return an encrypted message block
        """
        iv = os.urandom(16)
        result = {'iv': base64.b64encode(iv)}
        result['cipherText'] = base64.b64encode(
                aes.AES(key=hashlib.sha256('%s%s' % (
                    self.keyBundle['encryptionKey'].decode('hex'), 
                iv)).digest()).process(plaintext))
        result['hmac'] = hashlib.sha256("%s%s%s" % (self.keyBundle['hmac'], 
            result['cipherText'], self.keyBundle['url'])).hexdigest()
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
            raise CryptoException('Invalid HMAC')
        clearText = aes.AES(key=hashlib.sha256('%s%s' % (
            keyBundle['encryptionKey'].decode('hex'), 
            base64.b64decode(cryptBlock['iv']))
            ).digest()).process(base64.b64decode(cryptBlock['cipherText']))
        return clearText


if __name__ == '__main__':
    crypto = Crypto()
    testPhrase = 'This is a test'
    # The key bundle normally comes from the client. 
    # Generate a fake one for this test
    kb = crypto.generateKeyBundle()
    block = crypto.encrypt(testPhrase, kb)
    response = crypto.decrypt(block, kb)
    assert(response == testPhrase)
    print 'ok'
