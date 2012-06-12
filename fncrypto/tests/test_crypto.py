from fncrypto.crypto import FNCrypto
import unittest2


class FNCryptoTest(unittest2.TestCase):

    def setUp(self):
        self.crypto = FNCrypto()
        self.testPhrase = 'This is a test'

    def test_key_bundle(self):
        # Since the key bundle should come from the user agent,
        # generateKeyBundle is a testing call. Therefore we 
        # don't really need to test that. I do, but not rigourously.
       kb = self.crypto.generateKeyBundle()
       for element in ('encryptionKey', 'hmac', 'url'):
           self.assertIn(element, kb)
    
    def test_encrypt_decrypt(self):
        # Simple cycle. Take a phrase, encrypt, decrypt, compare.
        # if they match, you're good.
        kb = self.crypto.generateKeyBundle()
        block = self.crypto.encrypt(self.testPhrase, kb)
        for element in ('iv', 'cipherText', 'hmac'): 
            self.assertIn(element, block)
        response = self.crypto.decrypt(block, kb)
        self.assertEquals(response, self.testPhrase)
