var ursa = require("ursa");

var clearText='Encrypt and decrypt strings using RSA.';

var keySizeBits = 1024;
var keyPair = ursa.generatePrivateKey(keySizeBits, 65537);
var pubKey = ursa.createPublicKey(keyPair.toPublicPem());
var priKey = ursa.createPrivateKey(keyPair.toPrivatePem());

var rsaencrypted = encryptRSA(clearText, pubKey, keySizeBits/8);
console.log('String encrypted: '+rsaencrypted);

var rsadecrypted = decryptRSA(rsaencrypted, priKey, keySizeBits/8);
console.log('String decrypted: '+rsadecrypted);

function encryptRSA(clearText, pubKey, keySizeBytes){
    var buffer = new Buffer(clearText);
    var maxBufferSize = keySizeBytes - 42; //according to ursa documentation
    var bytesDecrypted = 0;
    var encryptedBuffersList = [];

    //loops through all data buffer encrypting piece by piece
    while(bytesDecrypted < buffer.length){
        //calculates next maximun length for temporary buffer and creates it
        var amountToCopy = Math.min(maxBufferSize, buffer.length - bytesDecrypted);
        var tempBuffer = new Buffer(amountToCopy);

        //copies next chunk of data to the temporary buffer
        buffer.copy(tempBuffer, 0, bytesDecrypted, bytesDecrypted + amountToCopy);

        //encrypts and stores current chunk
        var encryptedBuffer = pubKey.encrypt(tempBuffer);
        encryptedBuffersList.push(encryptedBuffer);

        bytesDecrypted += amountToCopy;
    }

    //concatenates all encrypted buffers and returns the corresponding String
    return Buffer.concat(encryptedBuffersList).toString('base64');
}

function decryptRSA(encryptedString, priKey, keySizeBytes){

    var encryptedBuffer = new Buffer(encryptedString, 'base64');
    var decryptedBuffers = [];

    //if the clear text was encrypted with a key of size N, the encrypted 
    //result is a string formed by the concatenation of strings of N bytes long, 
    //so we can find out how many substrings there are by diving the final result
    //size per N
    var totalBuffers = encryptedBuffer.length / keySizeBytes;

    //decrypts each buffer and stores result buffer in an array
    for(var i = 0 ; i < totalBuffers; i++){
        //copies next buffer chunk to be decrypted in a temp buffer
        var tempBuffer = new Buffer(keySizeBytes);
        encryptedBuffer.copy(tempBuffer, 0, i*keySizeBytes, (i+1)*keySizeBytes);
        //decrypts and stores current chunk
        var decryptedBuffer = priKey.decrypt(tempBuffer);
        decryptedBuffers.push(decryptedBuffer);
    }

    //concatenates all decrypted buffers and returns the corresponding String
    return Buffer.concat(decryptedBuffers).toString();
}

var crypto = require('crypto');
var text = 'Hello World!';
var hashed = hashText(text);
console.log('SHA256 hashed: ' + hashed);
var aesencrypted = encryptAES(text, hashed);
console.log('AES encrypted: ' + aesencrypted);
console.log('AES decrypted: ' + decryptAES(aesencrypted, hashed));

function hashText(text){
    var hash = crypto.createHmac('sha256', 'noonelivesforever');
    hash.update(text);
    return hash.digest('hex').toString();
}   

function encryptAES(text, key){
  var cipher = crypto.createCipher('aes-256-ctr', key);
  var crypted = cipher.update(text,'utf8','hex');
  crypted += cipher.final('hex');
  return crypted;
}
 
function decryptAES(text, key){
  var decipher = crypto.createDecipher('aes-256-ctr', key);
  var dec = decipher.update(text,'hex','utf8');
  dec += decipher.final('utf8');
  return dec;
}
