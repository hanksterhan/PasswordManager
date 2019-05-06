#!/usr/bin/env python3

""" Command line interface for password manager
"""

import sys, getopt, random, string, os.path
import passwordmeter
from passlib.hash import pbkdf2_sha256
import pandas as pd
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor
import pyperclip
from base64 import b64encode, b64decode



def password_strength(password, verboseFlag=0):
    """ Given a password as a string, calculate the password strength using the library passwordmeter and return True if the password is strong enough
        input: password (str), verboseFlag (int) default to 0 no printing, 1 to print
        output: True if the password is strong enough, False o.w.
    """
    strength, improvements = passwordmeter.test(password)
    if strength < 0.75:
        if verboseFlag:
            print("Your password is too weak, password strength: ", strength)
            print("Possible improvements:")
            for suggestion in improvements.values():
                print(" - ", suggestion)
            print() 
        return False
    else: 
        if verboseFlag:
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
    while not password_strength(mpassword, 1):
        mpassword = input("Please enter a strong password: ")
    # hash the pasword
    hash = hash_password(mpassword)

    # store the hash at the beginning of the dataframe
    passwords = pd.DataFrame({"password":[hash]})

    # save to file
    passwords.to_csv("passwords.txt", header=False)

    # create and save account/url dataframe
    metadata = pd.DataFrame({"Account Name": [], "url": []})
    metadata.to_csv("accounts.txt")

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

def store_password(mpassword):
    """ Generates a password key using 32 byte random salt and 500,000 rounds of stretching and encrypts the generated password
        Stores the password into the corresponding row in the dataframe
        input: mpassword (str)
        output: nothing
    """
    salt = get_random_bytes(32)
    pwdkey = PBKDF2(mpassword, salt, count=500000)
    del mpassword
    pw = generate_password().encode('utf-8')
    epw = strxor(pw, pwdkey)

    # copy generated password to clipboard
    pyperclip.copy(pw.decode('utf-8'))
    print("Password Copied to Clipboard")

    # save encrypted password to file
    newpwd = pd.DataFrame({"password":[b64encode(salt+epw)]})
    newpwd.to_csv('passwords.txt', mode='a', header=False)

def retrieve_password(mpassword, row):
    """ Given the row that the salt|encrypted_password is on, decrypt it
        input: row (int) 0-based index that starts after the hashed master password
                mpassword (str)
        output: nothing
    """
    # read in the encrypted password
    salt_epw = pd.read_csv("passwords.txt", skiprows=row, nrows=1).iat[0,1]
    salt_epw = b64decode(salt_epw[2:-1])
    salt = salt_epw[:32]
    epw = salt_epw[32:]

    pwdkey = PBKDF2(mpassword, salt, count=500000)
    del mpassword
    
    pw = strxor(epw, pwdkey)

    # copy generated password to clipboard
    pyperclip.copy(pw.decode('utf-8'))
    print("Password Copied to Clipboard")


def add_entry(mpassword, account='', url=''):
    """ Given an account name or url, create an entry in the dataframes and copy the password to the clipboard
        input: mpassword (str)
               account (str) [optional] account name if applicable
               url (str) [optional] url of the account if applicable
        output: nothing
    """
    # add metadata to the dataframes
    metadata = pd.DataFrame({"Account Name":[account], "url":[url]})
    metadata.to_csv('accounts.txt', mode='a', header=False)

    # add password to the password dataframe
    store_password(mpassword)

def search_entry(mpassword, account='', url=''):
    """ Given an account name or url, search the metadata dataframe to find the corresponding row entry 
        input: mpassword (str)
               account (str) [optional] account name if applicable
               url (str) [optional] url of the account if applicable
        output: nothing
    """
    # TODO: can make searches much more flexible than they are. ex: case insensitive account name, url only cares about what is after the www
    metadata = pd.read_csv('accounts.txt', index_col=0).reset_index()
    if account is not '':
        rowindex = metadata.index[metadata['Account Name'] == account].tolist()[0]
    elif url is not '':
        rowindex = metadata.index[metadata['url'] == url].tolist()[0]
    else:
        # TODO: what to do when account name nor url is found?
        print("Account entry not found. Please try again")
        sys.exit(2)
    retrieve_password(mpassword, rowindex)

def main():
    # check if the passwords file exists, it will exist if a master password has been established
    if not os.path.isfile('passwords.txt'): 
        create_master_password()

    # master password exists:
    else:
        try:
            opts, args = getopt.getopt(sys.argv[1:],'hp:')
        except getopt.GetoptError:
            print("Usage:  python3 manager.py -p <password> or\n\tpython3 manager.py to create a master password")
            sys.exit(2)

        mpassword = ''

        for opt, arg in opts:
            if opt == '-h':
                print("Usage:  python3 manager.py -p <password> or\n\tpython3 manager.py to create a master password")
                sys.exit()
            elif opt == '-p':
                mpassword = arg
    while True:
        action = int(input("What would you like to do? \n1 - print accounts \n2 - retrieve account password \n3 - add account\n4 - exit\n"))
        if action is 1: 
            # print accounts
            metadata = pd.read_csv('accounts.txt', index_col=0).reset_index(drop=True)
            print()
            print(metadata)
            del metadata
            print()

        elif action is 2:
            # retrieve account password
            print("retrieve account password")
        elif action is 3:
            # add account
            print("add account")
        elif action is 4:
            # exit
            print("exit")
            sys.exit(2)
        else: 
            # invalid option
            print("Please choose a valid option between 1, 2, and 3")
            sys.exit(2)

    # add_entry(mpassword, account='Facebook', url='www.facebook.com')
    # add_entry(mpassword, account='Gmail', url='www.gmail.com')
    # add_entry(mpassword, account='Twitter', url='www.twitter.com')
    # search_entry(mpassword, account='Twitter')

main()