/*global  console, CryptoJS, Uint8Array, Promise */

function runCrypto() {
    var ns = "cake.man.io";
    var passphrase = "My Test Password";
    var domain = "mrpeel@gmail.com";
    var seed, seedArray;


    console.log("Pass phrase: " + passphrase);
    console.log("Salt: " + ns);
    console.log("Domain: " + domain);


    //ns = CryptoJS.enc.Hex.parse("63616b652e6d616e2e696f");
    //use name space as salt
    //console.log('Derived key: ' + derivedKey);
    //hexKey = CryptoJS.enc.Hex.stringify(derivedKey);
    //console.log('Hex key: ' + derivedKey);

    return PBKDF2(passphrase, ns)
    .then(function(key){
        console.log('Derived key: ' + key);

        return CryptoJS.HmacSHA256(domain, key);
    }).then(function(seed){
        console.log('HMAC result seed hex: ' + seed);
        var seedArray =  convertWordArrayToUint8Array(seed);

        console.log('HMAC result seed array: ' + seedArray);
        console.log("All done"); 
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
    var len = wordArray.words.length,
        u8_array = new Uint8Array(len << 2),
        offset = 0,
        word, i;
    for (i = 0; i < len; i++) {
        word = wordArray.words[i];
        u8_array[offset++] = word >> 24;
        u8_array[offset++] = (word >> 16) & 0xff;
        u8_array[offset++] = (word >> 8) & 0xff;
        u8_array[offset++] = word & 0xff;
    }
    return u8_array;
}
