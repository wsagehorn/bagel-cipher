#!/usr/bin/env python3

import sys, os, hashlib, shutil, argparse, random, shutil


def get_args():
    parser = argparse.ArgumentParser()

    general_options = parser.add_argument_group("General Options")
    general_options.add_argument("-d", "--decrypt", dest="is_decrypt", action="store_true", default=False, help="Decrypt an encrypted file")
    general_options.add_argument("-v", "--verbose", dest="is_verbose", action="store_true", default=False, help="Print more about what's going on")
    general_options.add_argument("-c", "--cycles", dest="cycles", default=20, help="Number of cycles to run")
    general_options.add_argument("-w", "--window", dest="window_size", default=15, help="Print more about what's going on")

    io_options = parser.add_argument_group("I/O Options")
    io_options.add_argument('input_file')
    io_options.add_argument("-o", "--output", dest="output_file", help="File to output to. If left blank, save as inputfile.enc")
    io_options.add_argument("-k", "--key", dest="key_file", help="Key file. If left blank, will generate a key and save it as inputfile.key")
    io_options.add_argument("-s", "--string_key", dest="key_string", help="Key string, can be used instead of key file.")
    io_options.add_argument("-n", "--keysize", dest="key_size", default=128, help="size of the key to generate")
    io_options.add_argument("-r", "--directory", dest="is_directory", action="store_true", default=False, help="Encrypt  directory")

    return parser.parse_args()

def encrypt(a, b, k, cycles=20, window_size=15, verbose=False):
    iterations = cycles * 2
    k_index = 0
    a, b = xor(a, k), xor(b, k) # key whitening
    for i in range(iterations):
        a, b = xor(b, hash_and_subtract(a, k[k_index : k_index + window_size + 1])), a
        k_index = (k_index + 1) % (len(k) - window_size)
        if verbose:
            sys.stdout.write("\rencrypting...   %d%%" % ((1.0 * (i+1) / iterations) * 100))
            sys.stdout.flush()

    return xor(a, k) + xor(b, k) # more key whitening

def decrypt(a, b, k, cycles=20, window_size=15, verbose=False):
    iterations = cycles * 2
    a, b = xor(b, k), xor(a, k) #flip a and b and key whiten
    k_index = (iterations - 1) % (len(k) - window_size)
    for i in range(iterations):
        a, b = xor(b, hash_and_subtract(a, k[k_index : k_index + window_size + 1])), a
        k_index = (k_index - 1 + (len(k) - window_size)) % (len(k) - window_size)
        if verbose:
            sys.stdout.write("\r decrypting...   %d%%" % ((1.0 * (i+1) / iterations) * 100))
            sys.stdout.flush()
    return xor(b, k) + xor(a, k) #key whiten

def xor(x, y):
    result = bytearray()
    y_index = 0
    for b in x:
        result.append(b ^ y[y_index])
        y_index = (y_index + 1) % len(y)
    return result

#hashes both x and y, then subtracts y from x with byte underflow
def hash_and_subtract(x, y):
    x = bytearray(hashlib.md5(x).digest())
    y = bytearray(hashlib.md5(y).digest())
    result = bytearray()
    y_index = 0
    for b in x:
        result.append((b - y[y_index] + 256) % 256)
        y_index = (y_index + 1) % len(y)
    return result

def gen_key(key_length):
    key = bytearray()
    for i in range (0, key_length):
        key.append(random.randrange(0,256))
    return key

def main():
    args = get_args()

    input_file = args.input_file
    if args.is_directory and not args.is_decrypt:
        shutil.make_archive(input_file, 'zip', input_file)
        input_file += ".zip"

    if args.output_file:
        output_file = args.output_file
    else:
        if args.is_decrypt:
            output_file = input_file.replace(".enc","")
        else:
            output_file = input_file + ".enc"

    if args.key_string:
        key = args.key_string
    elif args.key_file:
        with open(args.key_file, "rb") as keyfile:
            key = keyfile.read()
    else:
        if args.is_decrypt:
            print("Error: Cannot decrypt without a key file")
            exit(1)
        with open(input_file + ".key", "wb") as keyfile:
            key = gen_key(args.key_size)
            keyfile.write(key)
            if args.is_verbose:
                print("generated key file named " + input_file + ".key")


    with open(input_file, "rb") as f:
        contents = f.read()
        middle = len(contents) // 2
        if args.is_decrypt:
            q = decrypt(bytearray(contents[:middle]), bytearray(contents[middle:]), bytearray(key),
                args.cycles, args.window_size, args.is_verbose)
            if args.is_verbose:
                print("\ndecrypted " + input_file)
        else:
            q = encrypt(bytearray(contents[:middle]), bytearray(contents[middle:]), bytearray(key),
                args.cycles, args.window_size, args.is_verbose)
            if args.is_verbose:
                print("\nencrypted " + input_file)
            if args.is_directory:
                os.remove(input_file)

        with open(output_file, "wb") as out:
            out.write(q)
            if args.is_verbose:
                print("wrote to " + output_file)
        if args.is_decrypt and args.is_directory:
            shutil.unpack_archive(output_file, output_file.replace(".zip", ""))
            os.remove(output_file)
            if args.is_verbose:
                print("unpacked to " + output_file.replace(".zip", ""))

if __name__ == "__main__":
    main()
