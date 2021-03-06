/*global  console, CryptoJS, Uint8Array, Promise, performance, TextEncoder, TextDecoder, window, webcrypto, crypto, CryptoFunctions */

var ns = "cake.man.io";
var passphrase = "My Special Pass phrase";
var domain = "mrpeel@mydomain.com.au";
var name = "Neil Kloot";
var plainText = "I hëart årt and £$¢!"; //"My secret message";
var seedHex1, seedHex2, seedHex3, seedHex4;
var encData, threeCharHash;

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


function encryptPassword() {
    var cryptoFunctions = new CryptoFunctions();

    console.log("Encrypt pass phrase");
    console.log("Using subtle cypto: " + cryptoFunctions.useSubtle);
    console.log("Pass phrase: " + passphrase);
    console.log("Salt: " + name + ns);
    console.log("Name: " + name);

    var aesKey;
    var firstThreeChars = passphrase.substring(0, 3);
    console.log("First three chars: " + firstThreeChars);


    cryptoFunctions.PBKDF2(name + firstThreeChars, name + ns, 500, 128)
        .then(function (key) {
            aesKey = cryptoFunctions.convertDerivedKeyToHex(key);
            console.log('Derived key hex: ' + aesKey);

            return cryptoFunctions.PBKDF2(cryptoFunctions.convertDerivedKeyToHex(key), name + firstThreeChars, 250, 128);
        }).then(function (verificationHash) {
            threeCharHash = cryptoFunctions.convertDerivedKeyToHex(verificationHash);
            console.log('Three char hash: ' + threeCharHash);

            return cryptoFunctions.AESEncrypt(passphrase, aesKey);
        }).then(function (encryptedData) {
            encData = encryptedData;

            console.log("Encrypted data: " + cryptoFunctions.convertDerivedKeyToHex(encryptedData.ciphertext));
            console.log("Encryption complete");
        });

}

function decryptPassword() {
    var cryptoFunctions = new CryptoFunctions();

    console.log("Decrypt pass phrase with wrong 3 chars");
    console.log("Using subtle cypto: " + cryptoFunctions.useSubtle);
    console.log("Pass phrase: " + passphrase);
    console.log("Salt: " + name + ns);
    console.log("Name: " + name);

    var aesKey;
    var firstThreeChars = passphrase.substring(0, 3);
    console.log("First three chars: " + firstThreeChars);


    cryptoFunctions.PBKDF2(name + firstThreeChars, name + ns, 500, 128)
        .then(function (key) {
            aesKey = cryptoFunctions.convertDerivedKeyToHex(key);
            console.log('Derived key hex: ' + aesKey);

            return cryptoFunctions.PBKDF2(cryptoFunctions.convertDerivedKeyToHex(key), name + firstThreeChars, 250, 128);
        }).then(function (verificationHash) {
            if (threeCharHash === cryptoFunctions.convertDerivedKeyToHex(verificationHash)) {
                console.log('Expected three char hash: ' + threeCharHash + ', Actual three char hash: ' + cryptoFunctions.convertDerivedKeyToHex(verificationHash));

                cryptoFunctions.AESDecrypt(encData, aesKey)
                    .then(function (plainText) {
                        console.log('Decrypted plain text: ' + plainText);
                        console.log("Decryption complete");
                    });

            } else {
                console.log('Expected three char hash: ' + threeCharHash + ', Actual three char hash: ' + cryptoFunctions.convertDerivedKeyToHex(verificationHash));
                console.log("Decryption suspended");
            }

        });

}

function failDecryptPassword() {
    var cryptoFunctions = new CryptoFunctions();

    console.log("Decrypt pass phrase with wrong 3 chars");
    console.log("Using subtle cypto: " + cryptoFunctions.useSubtle);
    console.log("Pass phrase: " + passphrase.substring(1));
    console.log("Salt: " + name + ns);
    console.log("Name: " + name);

    var aesKey;
    var firstThreeChars = passphrase.substring(1, 3);
    console.log("First three chars: " + firstThreeChars);


    cryptoFunctions.PBKDF2(name + firstThreeChars, name + ns, 500, 128)
        .then(function (key) {
            aesKey = cryptoFunctions.convertDerivedKeyToHex(key);
            console.log('Derived key hex: ' + aesKey);

            return cryptoFunctions.PBKDF2(cryptoFunctions.convertDerivedKeyToHex(key), name + firstThreeChars, 250, 128);
        }).then(function (verificationHash) {
            if (threeCharHash === cryptoFunctions.convertDerivedKeyToHex(verificationHash)) {
                return cryptoFunctions.AESDecrypt(encData, aesKey)
                    .then(function (plainText) {
                        console.log('Decrypted plain text: ' + plainText);
                        console.log("Decryption complete");
                    });

            } else {
                console.log('Expected three char hash: ' + threeCharHash + ', Actual three char hash: ' + cryptoFunctions.convertDerivedKeyToHex(verificationHash));
                console.log("Decryption suspended");
            }

        });

}
