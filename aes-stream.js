"use strict";

var crypto = require('crypto');
var stream = require('stream');

class AesStream extends stream.Transform {

    constructor(password, isEncryption, iterations, saltLength, onError) {
        super();
        this.isEncryption = isEncryption;
        this.algorithm = "aes-256-gcm";
        this.hashAlgorithm = "sha512";
        this.iterations = iterations ? iterations : 2007;
        this.saltLength = saltLength ? saltLength : 64;
        this.password = password;

        if (this.isEncryption) {
            this._initEncryption();
        } else {
            this._initDecryption();
        }

        this.on("error", (err) => {
            if (typeof onError == "function") {
                onError(err);
            }
            this.end();
        });
    }

    _initEncryption() {
        this.iv = crypto.randomBytes(12);
        this.salt = crypto.randomBytes(this.saltLength);
        this.key = crypto.pbkdf2Sync(this.password, this.salt, this.iterations, 32, this.hashAlgorithm);
        this.cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
    }

    _initDecryption() {
        this.data = [];
    }

    _transform(chunk, enc, callback) {
        try {
            var buffer = (Buffer.isBuffer(chunk)) ? chunk : new Buffer(chunk, enc);
            if (this.isEncryption) {
                this.push(this.cipher.update(buffer));
            } else {
                this.data.push(buffer);
            }
            callback();
        } catch (err) {
            callback(err);
        }
    }

    _flush(callback) {
        try {
            if (this.isEncryption) {
                this.push(this.cipher.final());
                var tag = this.cipher.getAuthTag();
                this.push(Buffer.concat([this.salt, this.iv, tag]));
            } else {
                this.data = Buffer.concat(this.data);
                var metaBegin = this.data.length - this.saltLength - 12 - 16;
                var salt = this.data.slice(metaBegin, metaBegin + this.saltLength);
                var iv = this.data.slice(metaBegin + this.saltLength, metaBegin + this.saltLength + 12);
                var tag = this.data.slice(metaBegin + this.saltLength + 12);
                var text = this.data.slice(0, metaBegin);
                var key = crypto.pbkdf2Sync(this.password, salt, this.iterations, 32, this.hashAlgorithm);
                var decipher = crypto.createDecipheriv(this.algorithm, key, iv);
                decipher.setAuthTag(tag);
                var decrypted = Buffer.concat([decipher.update(text), decipher.final()]);
                this.push(decrypted);
                this.data = [];
            }
            callback();
        } catch (err) {
            callback(err);
        }
    };
}

module.exports = AesStream;