"use strict";

var Aes = require("./aes");
var fs = require("fs");

var password = null;
var isEncrypt = false;
var fileOut = null;
var fileIn = null;

if (process.argv) {
    process.argv.forEach((arg) => {
        if (arg === "-e") {
            isEncrypt = true;
        } else if (arg.startsWith("-i")) {
            fileIn = arg.substring(2);
        } else if (arg.startsWith("-o")) {
            fileOut = arg.substring(2);
        } else if (arg.startsWith("-p")) {
            password = arg.substring(2);
        }
    });
}

if (!fileOut || !fileIn || !password) {
    console.error(`Usage:
\t-e - set encryption mode. Default decryption mode
\t-i - input file
\t-o - output file
\t-p - password\n\nExample:
\tencrypt: node app -e -i\"d:\\test.txt\" -o\"d:\\test.enc\" -pMyStrongPwd
\tdecrypt: node app -i\"d:\\test.enc\" -o\"d:\\decrypt.txt\" -pMyStrongPwd`);
    return;
}

var callback = function (err, resultData) {
    if (err) {
        console.error(fileIn, " -> ", fileOut, "failed. Error:", err);
        return;
    }
    fs.writeFile(fileOut, resultData, (err) => {
        if (err) {
            throw Error(err);
        }
        console.log(fileIn, " -> ", fileOut, "done");
    });
}

//use your own params for initialization Aes
var aes = new Aes(2007, 64);

if (isEncrypt) {
    aes.encryptFile(fileIn, password, callback);
} else {
    aes.decryptFile(fileIn, password, callback);
}
