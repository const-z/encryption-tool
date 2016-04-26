# encryption-tool
encryption/decryption tool

## Command line params
- -e - set encryption mode. Default decryption mode
- -i - input file
- -o - output file
- -p - password\n\nExample:

## Example
encrypt
```sh
node app -e -i\"d:\\test.txt\" -o\"d:\\test.enc\" -pMyStrongPwd
```
decrypt
```sh
node app -d -i\"d:\\test.enc\" -o\"d:\\test.dec\" -pMyStrongPwd`
```

