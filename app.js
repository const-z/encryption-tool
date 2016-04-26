"use strict";

var AesStream = require("./aes-stream");
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
\tdecrypt: node app    -i\"d:\\test.enc\" -o\"d:\\test.dec\" -pMyStrongPwd`);
    return;
}

var date = () => {
    return new Date().toISOString().replace(/T/, ' ');
}
var onError = (err) => {
    console.log(date(), "Error", err);
};
var onFinish = () => {
    console.log(date(), "Done");
}

var proc = new AesStream(password, isEncrypt, 2007, 64, onError);
var r = fs.createReadStream(fileIn);
console.log(date(), "Start");
var w = fs.createWriteStream(fileOut);
w.on("finish", onFinish);
r.pipe(proc).pipe(w);