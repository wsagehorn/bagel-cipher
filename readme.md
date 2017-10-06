### Bagel Cipher ###

by Walter Sagehorn and Christopher Gonzalez

A Feistel cipher that uses md5 for nonlinearity. Also uses key whitening.
Takes arbitrarily sized key and input file. Can also take directories as input.

```
usage: bagel.py [-h] [-d] [-v] [-c CYCLES] [-w WINDOW_SIZE] [-o OUTPUT_FILE]
                [-k KEY_FILE] [-s KEY_STRING] [-n KEY_SIZE] [-r]
                input_file

optional arguments:
  -h, --help            show this help message and exit

General Options:
  -d, --decrypt         Decrypt an encrypted file
  -v, --verbose         Print more about what's going on
  -c CYCLES, --cycles CYCLES
                        Number of cycles to run
  -w WINDOW_SIZE, --window WINDOW_SIZE
                        Print more about what's going on

I/O Options:
  input_file
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        File to output to. If left blank, save as
                        inputfile.enc
  -k KEY_FILE, --key KEY_FILE
                        Key file. If left blank, will generate a key and save
                        it as inputfile.key
  -s KEY_STRING, --string_key KEY_STRING
                        Key string, can be used instead of key file.
  -n KEY_SIZE, --keysize KEY_SIZE
                        size of the key to generate
  -r, --directory       Encrypt directory
```


## Sample Input: ##
  to encrypt:
    ./python bagel.py myfile.txt
      --> crypt.txt.enc
      --> crypt.txt.key (if one isn't provided)
  to decrypt:
    ./python bagel.py crypt.txt -d -k crypt.txt.key
      --> crypt.txt

  This also works on directories. (use the -r flag, it just zips/unzips them).

## Structure: ##
![I❤️flowcharts](https://raw.githubusercontent.com/wsagehorn/bagel-cipher/master/bagelcipher.png)
note:flowchart based largely on the one on the wikipedia page for Feistel ciphers
