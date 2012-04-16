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

    def __init__(self, storage=None):
        aes.start_up_self_test()
        if storage is not None:
            self.storage = storage
        else:
            self.storage = {};
        self.syncKey = base64.b32encode(
                os.urandom(self.bitSize / 8)).lower().replace('l', 
                        '8').replace('o', '9')

    def getUserToken(self, uid=0):
        token = self.storage.get(uid, {'uid': uid})
        #fetch user token from tokenServer:/1.0/fncrypto/1.0
        return token

    def setUserToken(self, uid=0, info={}):
        info.update({'uid': uid})
        self.storage[uid] = info
        return self.storage[uid]

    def generateKeyBundle(self, uid=None):
        if uid is None:
            uid = self.getUserToken().get('uid')
        if not hasattr(self, 'userToken'):
            self.userToken = self.getUserToken(uid)
        self.info = '%s%s' % (self.HMAC_INPUT, 
                self.userToken.get('uid'))
        self.encryptionKey = hashlib.sha256('%s%s\01' % (
                self.syncKey, self.info)).digest()
        self.keyBundle = {'encryptionKey': self.encryptionKey,
            'hmac': hashlib.sha256('%s%s\02' % (self.encryptionKey,
                self.info)).digest()}
        #self.storage(uid, 'keyBundle', self.keyBundle)
        self.setUserToken(uid, self.keyBundle)
        return self.keyBundle

    def getKeyBundle(self, uid):
        if self.keyBundle:
            return self.keyBundle
        #fetch the keyBundle from "storage"
        # else:
        return self.generateKeyBundle(self, uid)

    def encrypt(self, plaintext, uid=None, iv=None):
        """ encrypt a block of plaintext.
        note: uid = unique identifier (possibly user id + site id)
        """
        if iv is None:
            iv = os.urandom(16)
        if uid is None:
            uid = self.getUserToken().get('uid')
        if not hasattr(self, 'keyBundle'):
            self.getKeyBundle(uid)
        result = {'iv': base64.b64encode(iv)}
        result['cipherText'] = base64.b64encode(
                aes.AES(key=hashlib.sha256('%s%s' % (
                    self.keyBundle['encryptionKey'], 
                iv)).digest()).process(plaintext))
        result['hmac'] = hashlib.sha256("%s%s" % (self.keyBundle['hmac'], 
            result['cipherText'])).hexdigest()
        return result

    def decrypt(self, cryptBlock, uid=None):
        if uid is None:
            uid = self.getUserToken().get('uid')
        if not hasattr(self, 'keyBundle'):
            self.getKeyBundle(uid)
        localHmac = hashlib.sha256('%s%s' % (self.keyBundle['hmac'],
            cryptBlock['cipherText'])).hexdigest()
        if localHmac != cryptBlock['hmac']:
            raise CryptoException('Invalid HMAC')
        clearText = aes.AES(key=hashlib.sha256('%s%s' % (
            self.keyBundle['encryptionKey'], 
            base64.b64decode(cryptBlock['iv']))
            ).digest()).process(base64.b64decode(cryptBlock['cipherText']))
        return clearText


if __name__ == '__main__':
    crypto = Crypto()
    testPhrase = 'This is a test'
    kb = crypto.generateKeyBundle()
    block = crypto.encrypt(testPhrase)
    response = crypto.decrypt(block)
    assert(response == testPhrase)
    print 'ok'
