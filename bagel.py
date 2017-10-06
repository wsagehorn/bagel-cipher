
import os, hashlib, shutil, argparse

ITERATIONS  = 400 # must be even
LOW_BOUND_KEY_LEN = 15 # keys must be longer than this, window size is LOW_BOUND_KEY_LEN + 1

def get_args():
    parser = argparse.ArgumentParser()

    general_options = parser.add_argument_group("General Options")
    general_options.add_argument("-v", "--verbose", dest="is_verbose", help="Print more about what's going on")
    general_options.add_argument("-c", "--cycles", dest="cycles", help="Number of cycles to run")
    general_options.add_argument("-w", "--window", dest="window_size", help="Print more about what's going on")

    io_options = parser.add_argument_group("I/O Options")
    io_options.add_argument('input')
    io_options.add_argument("-o", "--output", dest="output_file", help="File to output to. If left blank, save as inputfile.enc")
    io_options.add_argument("-k", "--key", dest="key_file", help="Key file. If left blank, will generate a key and save it as inputfile.key")
    io_options.add_argument("-r", "--directory", dest="is_directory", action="store_true", default=False, help="Encrypt  directory")

    return parser.parse_args()

def enc(a, b, k):
    k_index = 0
    for i in range(ITERATIONS):
        a, b = xor(b, hash_and_subtract(a, k[k_index : k_index + LOW_BOUND_KEY_LEN + 1])), a
        k_index = (k_index + 1) % (len(k) - LOW_BOUND_KEY_LEN)
    return a + b

def dec(a, b, k):
    a, b = b, a
    k_index = (ITERATIONS - 1) % (len(k) - LOW_BOUND_KEY_LEN)
    for i in range(ITERATIONS):
        a, b = xor(b, hash_and_subtract(a, k[k_index : k_index + LOW_BOUND_KEY_LEN + 1])), a
        k_index = (k_index - 1 + (len(k) - LOW_BOUND_KEY_LEN)) % (len(k) - LOW_BOUND_KEY_LEN)
    return b + a

def xor(x, y):
    result = bytearray()
    y_index = 0
    for b in x:
        result.append(b ^ y[y_index])
        y_index = (y_index + 1) % len(y)
    return result

#hashes both x and y, then subtracts y from x with byte underflow
def hash_and_subtract(x, y):
    x = bytearray(hashlib.sha256(x).digest())
    y = bytearray(hashlib.sha256(y).digest())
    result = bytearray()
    y_index = 0
    for b in x:
        result.append((b - y[y_index] + 256) % 256)
        y_index = (y_index + 1) % len(y)
    return result

def main():

    args = get_args()
"""
    general_options.add_argument("-v", "--verbose", dest="is_verbose", help="Print more about what's going on")
    general_options.add_argument("-c", "--cycles", dest="cycles", help="Number of cycles to run")
    general_options.add_argument("-w", "--window", dest="window_size", help="Print more about what's going on")

    io_options = parser.add_argument_group("I/O Options")
    io_options.add_argument('input')
    io_options.add_argument("-o", "--output", dest="output_file", help="File to output to. If left blank, save as inputfile.enc")
    io_options.add_argument("-k", "--key", dest="key_file", help="Key file. If left blank, will generate a key and save it as inputfile.key")
    io_options.add_argument("-s", "--string_key", dest="key_string", help="Key string, can be used instead of key file.")

    """


    filename = args.input
    if args.key_string:
        key = args.key_string
    else:
        with open(args.key_file, "rb") as keyfile:
            key = keyfile.read()
    

    key = "walter is cool walter is cool walter is cool"

    with open(filename, "rb") as f:
        contents = f.read()
        middle = len(contents) / 2
        q = enc(bytearray(contents[:middle]), bytearray(contents[middle:]), bytearray(key))
        print q
        print dec(q[:middle], q[middle:], bytearray(key))

if __name__ == "__main__":
    main()
