=fnCrypto

(This is abandonware. The spec changed, and this module is no longer required. It's still here for historical 
and educational purposes.)

Firefox Notifications crypto support

== Currently supported libraries:
Javascript - /js
    Use:
        # keyBundle from remote client
        encryptedBlock = FNCrypto.encrypt(plainText, keyBundle);
        plainTextObject = FNCrypto.decrypt(encryptedBlock, keyBundle);

Python - /fncrypto
    use:
        from fncrypto.crypto import (FNCrypto, FNCryptoException)

        fncrypto = FNCrypto()
        # keyBundle from client
        encryptedBlock = fncrypto.encrypt(plainText, keyBundle)
        plainText = fncrypto.decrypt(encryptedBlock, keyBundle)

Perl - /otherLanguages/perl
        in process

PHP - TBD

Ruby, Haskell, C++, Java, ObjectiveC, .net, eLisp, COBOL, REXX, Logo, TurboPascal, etc. -
    probably best if you wrote that.

