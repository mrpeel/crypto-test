/*global  console, CryptoJS, Uint8Array, Promise, performance, TextEncoder, TextDecoder, window, webcrypto, crypto, CryptoFunctions */

var ns = "cake.man.io";
var passphrase = "My Special Pass phrase";
var domain = "mrpeel@mydomain.com.au";
var plainText = "I hëart årt and £$¢!"; //"My secret message";
var seedHex1, seedHex2, seedHex3, seedHex4;

function runCrypto() {
    var seed, seedArray;
    var t0 = performance.now();


    console.log("CryptoJS ->Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);


    //ns = CryptoJS.enc.Hex.parse("63616b652e6d616e2e696f");
    //use name space as salt
    //console.log('Derived key: ' + derivedKey);
    //hexKey = CryptoJS.enc.Hex.stringify(derivedKey);
    //console.log('Hex key: ' + derivedKey);

    return PBKDF2(passphrase, ns)
        .then(function (key) {
            var keyArray = convertWordArrayToUint8Array(key);
            console.log('Key array: ' + keyArray);
            console.log('Key hex: ' + convertUint8ArrayToHex(keyArray));

            return CryptoJS.HmacSHA256(domain, key);
        }).then(function (seed) {
            console.log('HMAC result seed hex: ' + seed);
            var seedArray = convertWordArrayToUint8Array(seed);
            seedHex1 = convertUint8ArrayToHex(seedArray);

            console.log('HMAC result seed array: ' + seedArray);
            console.log("All done");
            console.log(performance.now() - t0 + " ms");
        });
}

function useClassCryptoJS() {
    var cryptoFunctions = new CryptoFunctions();
    cryptoFunctions.useSubtle = false;


    console.log("Class Crypto JS -> Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));

            return cryptoFunctions.HMACSHA256(domain, key);
        }).then(function (seed) {
            seedHex3 = cryptoFunctions.convertUint8ArrayToHex(seed);
            console.log('HMAC result seed hex: ' + seedHex3);

            console.log('HMAC result seed array: ' + seed);
            console.log("All done");
        });

}

function useSubtleCrypto() {

    console.log("Subtle -> Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);


    var cryptoTextEncoder = new TextEncoder("utf-8");
    var cryptoTextDecoder = new TextDecoder("utf-8");

    // salt should be Uint8Array or ArrayBuffer
    var saltBuffer = cryptoTextEncoder.encode(ns);

    var passphraseKey = cryptoTextEncoder.encode(passphrase);

    var domainBuffer = cryptoTextEncoder.encode(domain);

    crypto.subtle.importKey('raw', passphraseKey, {
            name: 'PBKDF2'
        }, false, ['deriveBits']).then(function (key) {
            return crypto.subtle.deriveBits({
                name: 'PBKDF2',
                iterations: 750,
                salt: saltBuffer,
                hash: 'SHA-1'
            }, key, 128);
        }).then(function (derivedKey) {
            var uint8Key = new Uint8Array(derivedKey);
            console.log('Derived key hex: ' + convertUint8ArrayToHex(uint8Key));

            return crypto.subtle.importKey("raw", derivedKey, {
                name: "HMAC",
                hash: {
                    name: "SHA-256"
                }
            }, false /*not extractable*/ , ["sign"]);
        })
        .then(function (importedKey) {
            return window.crypto.subtle.sign({
                name: "HMAC",
                hash: {
                    name: "SHA-256"
                }
            }, importedKey, domainBuffer);
        })
        .then(function (seed) {
            var seedArray = new Uint8Array(seed);
            seedHex2 = convertUint8ArrayToHex(seedArray);
            console.log('HMAC result seed hex: ' + seedHex2);
            console.log('HMAC result seed array:' + seedArray);

        });
}

function useClassSubtleCrypto() {
    var cryptoFunctions = new CryptoFunctions();


    console.log("Class Subtle Crypto -> Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Derived key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));

            return cryptoFunctions.HMACSHA256(domain, key);
        }).then(function (seed) {
            seedHex4 = cryptoFunctions.convertUint8ArrayToHex(seed);
            console.log('HMAC result seed hex: ' + seedHex4);

            console.log('HMAC result seed array: ' + seed);
            console.log("SeedHex1: " + seedHex1);
            console.log("SeedHex2: " + seedHex2);
            console.log("SeedHex3: " + seedHex3);
            console.log("SeedHex4: " + seedHex4);
            console.log("SeedHex1 = SeedHex2 = SeedHex3 = SeedHex4: " + (seedHex1 === seedHex2 && seedHex2 === seedHex3 && seedHex3 === seedHex4));
            console.log("All done");
        });

}

function encryptDecryptCryptoJS() {
    var cryptoFunctions = new CryptoFunctions();
    cryptoFunctions.useSubtle = false;

    var keyHolder;

    console.log("Class Crypto JS -> Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Plain text: " + plainText);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));
            keyHolder = cryptoFunctions.convertDerivedKeyToHex(key);

            return cryptoFunctions.AESEncrypt(plainText, keyHolder);
        }).then(function (encryptedData) {
            //console.table(encryptedData);
            console.log(cryptoFunctions.convertWordArrayToHex(encryptedData.ciphertext));

            return cryptoFunctions.AESDecrypt(encryptedData, keyHolder);
        }).then(function (plainText) {
            console.log('Decrypted plain text: ' + plainText);

        });

}

function encryptDecryptSubtleCrypto() {
    var cryptoFunctions = new CryptoFunctions();
    cryptoFunctions.useSubtle = true;

    var keyHolder;

    console.log("Class Subtle Crypto -> Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Plain text: " + plainText);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));
            keyHolder = cryptoFunctions.convertDerivedKeyToHex(key);

            return cryptoFunctions.AESEncrypt(plainText, keyHolder);
        }).then(function (encryptedData) {
            //console.table(encryptedData);
            console.log(cryptoFunctions.convertUint8ArrayToHex(encryptedData.ciphertext));

            return cryptoFunctions.AESDecrypt(encryptedData, keyHolder);
        }).then(function (plainText) {
            console.log('Decrypted plain text: ' + plainText);

        });

}

function PBKDF2Crypto() {
    var cryptoFunctions = new CryptoFunctions();

    console.log("PBKDF2");
    console.log("Using subtle cypto: " + cryptoFunctions.useSubtle);
    console.log("Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Derived key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));

            return cryptoFunctions.HMACSHA256(domain, key);
        }).then(function (seed) {
            seedHex4 = cryptoFunctions.convertUint8ArrayToHex(seed);
            console.log('HMAC result seed hex: ' + seedHex4);

            console.log('HMAC result seed array: ' + seed);
        });

}

function encryptDecryptCrypto() {
    var cryptoFunctions = new CryptoFunctions();

    var keyHolder;

    console.log("AES Encrypt and Decrypt");
    console.log("Using subtle cypto: " + cryptoFunctions.useSubtle);
    console.log("Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Plain text: " + plainText);



    cryptoFunctions.PBKDF2(passphrase, ns, 750, 128)
        .then(function (key) {
            console.log('Key hex: ' + cryptoFunctions.convertDerivedKeyToHex(key));
            keyHolder = cryptoFunctions.convertDerivedKeyToHex(key);

            return cryptoFunctions.AESEncrypt(plainText, keyHolder);
        }).then(function (encryptedData) {
            console.log(cryptoFunctions.convertDerivedKeyToHex(encryptedData.ciphertext));

            return cryptoFunctions.AESDecrypt(encryptedData, keyHolder);
        }).then(function (plainText) {
            console.log('Decrypted plain text: ' + plainText);

        });

}


function PBKDF2(passphrase, salt) {
    return new Promise(function (resolve, reject) {
        var derivedKey = CryptoJS.PBKDF2(passphrase, salt, {
            iterations: 750,
            keySize: 128 / 32
        });

        resolve(derivedKey);
    });

}

function HMACSHA256(plainText, key) {
    return new Promise(function (resolve, reject) {
        var seed = CryptoJS.HmacSHA256(plainText, key);

        resolve(seed);
    });

}

function convertWordArrayToUint8Array(wordArray) {
    var words = wordArray.words;
    var sigBytes = wordArray.sigBytes;

    // Convert
    var u8 = new Uint8Array(sigBytes);
    for (var i = 0; i < sigBytes; i++) {
        var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        u8[i] = byte;
    }

    return u8;
}

function convertUint8ArrayToHex(u8Array) {
    var i;
    var len;
    var hex = '';
    var c;

    for (i = 0, len = u8Array.length; i < len; i += 1) {
        c = u8Array[i].toString(16);
        if (c.length < 2) {
            c = '0' + c;
        }
        hex += c;
    }

    return hex;
}
