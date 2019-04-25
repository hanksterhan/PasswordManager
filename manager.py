#!/usr/bin/env python2

""" Command line interface for password manager
"""

import sys, getopt, random, string
import passwordmeter
from passlib.hash import pbkdf2_sha256
import pandas as pd

try:
    opts, args = getopt.getopt(sys.argv[1:],'hp:')
except getopt.GetoptError:
    print("Usage: manager.py -p <password>")
    sys.exit(2)

mpassword = ''

for opt, arg in opts:
    if opt == '-h':
        print("Usage: manager.py -p <password>")
        sys.exit()
    elif opt == '-p':
        mpassword = arg

def password_strength(password):
    """ Given a password as a string, calculate the password strength using the library passwordmeter and return True if the password is strong enough
        input: password (str)
        output: True if the password is strong enough, False o.w.
    """
    strength, improvements = passwordmeter.test(password)
    if strength < 0.75:
        print("Your password is too weak, password strength: ", strength)
        print("Possible improvements:")
        for suggestion in improvements.values():
            print(" - ", suggestion)
        print() 
        return False
    else: 
        print("Your password is strong! Password strength: ", strength)
        return True

def hash_password(password):
    """ Given a password, hash it with PBKDF2 with 32 byte salt and 500,000 rounds of stretching. return the hash
        input: password (str)
        output: hash (str)
    """
    hash = pbkdf2_sha256.encrypt(password, rounds = 500000, salt_size=32)
    return hash

def verify_password(password):
    """ Given a password, read in the mpassword hash and verify that the password is indeed the correct mpassword
        input: password (str)
        output: True for successful verification
                False for unsuccessful verification
    """
    # read in the csv and access the hash
    hash = pd.read_csv("passwords.txt", nrows=1).iat[0,1]
    return(pbkdf2_sha256.verify(password, hash))

def create_master_password():
    """ Logic to prompt users to create master password
    """
    mpassword = input("Please enter a strong password: ")
    while not password_strength(mpassword):
        mpassword = input("Please enter a strong password: ")
    # hash the pasword
    hash = hash_password(mpassword)

    # store the hash at the beginning of the dataframe
    passwords = pd.DataFrame({"password":[hash]})

    # save to file
    passwords.to_csv("passwords.txt")

def generate_password():
    """ Generates a password of length 16 using cryptographic grade random bits. Must have a password strength over 0.75
        output: randomly generated password
    """
    myrg = random.SystemRandom()
    length = 16
    alphabet = string.ascii_letters + string.digits + '!'+'@'+'#'+'$'+'%'+'^'+'&'+'*'+'('+')'

    pw = str().join(myrg.choice(alphabet) for _ in range(length))
    while not password_strength(pw):
        pw = str().join(myrg.choice(alphabet) for _ in range(length))
    return(pw)

# create_master_password()
# generate_password()
