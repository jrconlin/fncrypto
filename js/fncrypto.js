"use strict";

    function FNCryptoException(message) {
            this.message = message;
    }

    FNCryptoException.prototype = new(Error);

    function FNCrypto() {
        var self = this;

        // Encryption bit size (higher is better)
        self._bitSize = 256;
        // The local "app name" (you probably want to change this)
        self._myAppName = 'fnCryptoClient';

        // -- Protected Functions
        // These functions may change or be dropped. Direct use is not advised. 
        /** generate a sting of random characters 
         *
         * @param bitLen bit length of string to generate (defaults to self._bitSize)
         */
        self._randString = function(bitLen) {
            var val=""
            if (bitLen == undefined) {
                bitLen = self._bitSize;
            }
            //var chars = sjcl.codec.base64._chars;
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            var charsLen = chars.length;
            for (var i=0; i < bitLen/8; i++) {
                val += chars[Math.floor(Math.random() * charsLen)];
            }
            return val;
        }

        /** Generate a site key 
         *
         */
        self._newSiteKey = function() {
            var bits = 0;
            return Math.round(Math.random() * Math.pow(2, self._bitSize));
        }

        /** Fetch from storage 
         *
         * Currently uses localStorage, but may be overwritten to use any other key/value data store.
         */
        self._getStorage = function(key) {
            if (key == undefined) {
                key = self._getSite() + '-kb';
            }
            var storeInfo = sessionStorage.getItem(key);
            if (storeInfo != undefined) {
                storeInfo = JSON.parse(storeInfo);
            }
            return storeInfo;
        }

        self._setStorage = function(key, info) {
            sessionStorage.setItem(key, JSON.stringify(info));
        }

        self._getSite = function(){
            return document.location.protocol + document.location.host;
        }

        // -- Public functions
        // Effort will be made to keep these functions stable across the current Major version.

        /** retrieve/generate the "key bundle" for this site.
         *
         * @param site The site name (e.g. 'example.com') This is used as a key by the client
         *
         * Key Bundle consists of an object containing:
         *    "site" protocol:sitename of the originating site.
         *    "encryptionKey": Encryption/Decryption key.
         *    "hmac": HMAC value for signing the cipherText
         *
         * Content is currently stored in localStorage. Key Bundle is private and
         * MUST NOT be shared.
         */
        self.getKeyBundle = function(site) {
            var keyBundle;
            if (site == undefined) {
                site = self._getSite();
            }
            keyBundle = self._getStorage(site + '-kb')
            if (keyBundle != undefined) {
                return keyBundle
            }
            var info = self._myAppName + "-AES_256_CBC-HMAC256" + site;
            var siteKey = self._newSiteKey();
            var encryptionKey = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(siteKey + info + "\x01"));
            var keyBundle = {'site': site,
                'encryptionKey': encryptionKey,
                'hmac': sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(encryptionKey + info + "\x02"))};
            self._setStorage(site + '-kb', keyBundle);
            return keyBundle;
        }

        /** encrypt a plaintext string
         *
         * @param plaintext   the plaintext string to encrypt
         * @param site        site name (used as a key for client decryption
         * @param keyBundle   secret key bundle to encrypt the content
         * @param iv          optional Initialization Vector for encryption
         *
         * @return a cryptoBlock structure
         */
        self.encrypt = function(plainText, site, keyBundle, iv) {
            if (plainText == undefined) {
                throw new FNCryptoException('nothing to encrypt');
            }
            if (site == undefined) {
                site = self._getSite();
            }
            if (keyBundle == undefined) {
                keyBundle = self.getKeyBundle(site);
            }
            // generate a new IV if one wasn't provided.
            if (iv == undefined) {
                iv = sjcl.codec.base64.toBits(self._randString());
            }
            var key = sjcl.hash.sha256.hash(sjcl.codec.hex.fromBits(sjcl.codec.hex.toBits(keyBundle.encryptionKey).concat(iv)));
            var aes = new sjcl.cipher.aes(key);
            var ptArray = sjcl.codec.utf8String.toBits(plainText);
            // bring the array to a 4 byte boundry
            if (ptArray.length % 4 != 0) {
                ptArray = ptArray.concat([0,0,0].splice(0, 4 - ptArray.length % 4));
            }
            var ptArrayLen = ptArray.length;
            var bag = [];
            for (var i=0;i<ptArrayLen; i+=4) {
                var items = ptArray.splice(0,4);
                try {
                    aes.encrypt(items).forEach(function(v){bag.push(v)});
                } catch (e) {
                    console.error('Invalid data size (', ptArrayLen, '). Could not encrypt block. Please file a bug.');
                }
            }
            var cipherText = sjcl.codec.base64.fromBits(bag);
            var hmac = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(keyBundle.hmac + cipherText + site));
            return {'iv': sjcl.codec.base64.fromBits(iv),
                'cipherText': cipherText,
                'site': site,
                'hmac': hmac}
        }

        /** Decrypt content returned from an "encrypt" call.
         *
         * @param site    protocol + host name for origin site.
         * @param cryptBlock the encrypted info
         * @param keyBundle optional keyBundle to use instead of the one stored for site
         * 
         * The cryptBlock is an object that contains the following:
         * { 'iv': base64 encoded Init Vector for this block.
         *   'cipherText': base64 encoded, AES encrypted text
         *   'hmac': HMAC for the cypherText derived from the keyBundle HMAC
         * }
         *
         * @return an object containing:
         * {
         *  'plainText': The UTF8 encoded string containing the decrypted content.
         * }
         *
         */
        self.decrypt = function(cryptBlock, site, keyBundle) {
            if (cryptBlock == undefined) {
                return undefined;
            }
            if (site == undefined) {
                if (cryptBlock.hasOwnProperty('site')) {
                    site = cryptBlock.site;
                } else {
                    site = self._getSite();
                }
            }
            if (keyBundle == undefined) {
                keyBundle = self.getKeyBundle(site);
            }
            // check the hmac
            var localmac = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(keyBundle.hmac + cryptBlock.cipherText + site));
            if (localmac != cryptBlock.hmac) {
                throw new FNCryptoException('bad mac');
            }
            var iv = sjcl.codec.base64.toBits(cryptBlock.iv);
            var key = sjcl.hash.sha256.hash(sjcl.codec.hex.fromBits(sjcl.codec.hex.toBits(keyBundle.encryptionKey).concat(iv)));
            var aes = new sjcl.cipher.aes(key);
            var ptArray = sjcl.codec.base64.toBits(cryptBlock.cipherText);
            // Again, make sure that the AES is on a 4 byte boundry
            if (ptArray.length % 4 != 0) {
                ptArray = ptArray.concat([0,0,0].splice(0, 4 - ptArray.length % 4));
            }
            var ptArrayLen = ptArray.length;
            var bag = [];
            for (var i=0; i <= ptArrayLen; i += 4) {
                var items = ptArray.splice(0,4);
                try {
                    aes.decrypt(items).forEach(function(v){bag.push(v)});
                } catch (e) {
                    console.error('Invalid data size (', ptArrayLen, '). Could not decrypt block. Please file a bug.');
                    throw(e);
                }
            }
            // strip extra NULLs off the end of the string.
            var plainText = sjcl.codec.utf8String.fromBits(bag).replace(/\x00*$/, '');
            return {'plainText': plainText}
        }

        /** Have we registered a key bundle for this site?
         *
         * @param site   site name
         */
        function isRegistered(site) {
            return self._getStorage(site + '-kb') !=  undefined;
        }
    }
