"use strict";

var crypto = require("crypto");
var fs = require("fs");

class Aes {

    constructor(iterations, saltLength) {
        this.iterations = iterations;
        this.algorithm = "aes-256-gcm";
        this.hashAlgorithm = "sha512";
        this.saltLength = saltLength;
    }

    encryptFile(fileIn, password, callback) {
        fs.readFile(fileIn, (err, data) => {
            if (err) {
                throw Error(err);
            }
            try {
                var e = this.encrypt(data, password);
                callback(null, e);
            } catch (err) {
                callback(err);
            }
        });
    }

    decryptFile(fileIn, password, callback) {
        fs.readFile(fileIn, (err, data) => {
            if (err) {
                throw Error(err);
            }
            try {
                var e = this.decrypt(data, password);
                callback(null, e);
            } catch (err) {
                callback(err);
            }
        });
    }

    encrypt(data, password) {
        var iv = crypto.randomBytes(12);
        var salt = crypto.randomBytes(this.saltLength);
        var key = crypto.pbkdf2Sync(password, salt, this.iterations, 32, this.hashAlgorithm);
        var cipher = crypto.createCipheriv(this.algorithm, key, iv);
        var encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        var tag = cipher.getAuthTag();
        return Buffer.concat([salt, iv, tag, encrypted]).toString("base64");
    }

    decrypt(data, password) {
        var buffer = new Buffer(data.toString("ascii"), "base64");
        var salt = buffer.slice(0, this.saltLength);
        var iv = buffer.slice(this.saltLength, this.saltLength + 12);
        var tag = buffer.slice(this.saltLength + 12, this.saltLength + 12 + 16);
        var text = buffer.slice(this.saltLength + 12 + 16);
        var key = crypto.pbkdf2Sync(password, salt, this.iterations, 32, this.hashAlgorithm);
        var decipher = crypto.createDecipheriv(this.algorithm, key, iv);
        decipher.setAuthTag(tag);
        var decrypted = Buffer.concat([decipher.update(text), decipher.final()]);
        return decrypted;
    }
};

module.exports = Aes;