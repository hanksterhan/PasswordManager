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
import getpass



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
    print("Welcome to secure password management!\nTo begin, please create a strong password - remember to use both uppercase and lowercase letters, numbers, and symbols.\n")

    mpassword = getpass.getpass("Please enter a strong password: ")
    while not password_strength(mpassword, 1):
        mpassword = getpass.getpass("Please enter a strong password: ")

    # confirm password
    mpassword2 = getpass.getpass("\nPlease confirm password:")
    
    incorrect_counter = 0
    while mpassword != mpassword2:
        # Maximum attempts reached
        if incorrect_counter is 4:  
            print("Maximum attempts reached. Please restart and try again.")
            sys.exit()

        # If passwords don't match
        print("\nPasswords don't match")
        mpassword2 = getpass.getpass("Please confirm password:")
        incorrect_counter += 1
    print("Password matched!\n")

    print("Password created!\nWARNING: if this password is lost, the password cannot be retrieved and the password database will be lost.\n")
    # hash the pasword
    hash = hash_password(mpassword)

    # delete the master password:
    del mpassword

    # store the hash at the beginning of the dataframe
    passwords = pd.DataFrame({"password":[hash]})

    # save to file
    passwords.to_csv("passwords.txt")

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

def store_password():
    """ Generates a password key using 32 byte random salt and 500,000 rounds of stretching and encrypts the generated password
        Stores the password into the corresponding row in the dataframe
        input: nothing
        output: nothing
    """
    salt = get_random_bytes(32)

    # Prompt and verify mpassword
    mpassword = getpass.getpass("\nPlease enter master password: ")

    incorrect_counter = 0
    while(incorrect_counter < 10):
        if not verify_password(mpassword):
            print("Password incorrect.\n")

            mpassword = getpass.getpass("Please enter master password: ")
            print()

            incorrect_counter += 1

            # Too many failed attempts, delete password database. 
            if incorrect_counter == 9:
                os.remove('accounts.txt')
                os.remove('passwords.txt')
                print("Password database deleted.")
                sys.exit(2)
        else:
            break

        if incorrect_counter > 5:
            print("Nearing maximum password attempts, deleting password database in  {} attempts.".format(9-incorrect_counter))

    pwdkey = PBKDF2(mpassword, salt, count=500000)

    # delete master password from memory 
    del mpassword

    pw = generate_password().encode('utf-8')
    epw = strxor(pw, pwdkey)

    # copy generated password to clipboard
    pyperclip.copy(pw.decode('utf-8'))
    print("\nPassword Copied to Clipboard\n")

    # save encrypted password to file
    newpwd = pd.DataFrame({"password":[b64encode(salt+epw)]})
    newpwd.to_csv('passwords.txt', mode='a', header=False)

def retrieve_password(row):
    """ Given the row that the salt|encrypted_password is on, decrypt it
        input: row (int) 0-based index that starts after the hashed master password
        output: nothing
    """
    # read in the encrypted password
    salt_epw = pd.read_csv("passwords.txt", skiprows=row, nrows=1).iat[0,1]
    salt_epw = b64decode(salt_epw[2:-1])
    salt = salt_epw[:32]
    epw = salt_epw[32:]
    
    # Prompt and verify mpassword
    mpassword = getpass.getpass("\nPlease enter master password: ")

    incorrect_counter = 0
    while(incorrect_counter < 10):
        if not verify_password(mpassword):
            print("Password incorrect.\n")

            mpassword = getpass.getpass("Please enter master password: ")
            print()

            incorrect_counter += 1

            # Too many failed attempts, delete password database. 
            if incorrect_counter == 9:
                os.remove('accounts.txt')
                os.remove('passwords.txt')
                print("Password database deleted.")
                sys.exit(2)
        else:
            break

        if incorrect_counter > 5:
            print("Nearing maximum password attempts, deleting password database in  {} attempts.".format(9-incorrect_counter))

    pwdkey = PBKDF2(mpassword, salt, count=500000)

    # delete master password
    del mpassword
    
    pw = strxor(epw, pwdkey)

    # copy generated password to clipboard
    pyperclip.copy(pw.decode('utf-8'))
    print("\nPassword Copied to Clipboard! \n")


def add_entry(account='', url=''):
    """ Given an account name or url, create an entry in the dataframes and copy the password to the clipboard
        input: mpassword (str)
               account (str) [optional] account name if applicable
               url (str) [optional] url of the account if applicable
        output: nothing
    """
    # add metadata to the dataframes
    metadata = pd.DataFrame({"Account Name":[account.lower()], "url":[url.lower()]})
    metadata.to_csv('accounts.txt', mode='a', header=False)

    # add password to the password dataframe
    store_password()

def search_entry(account='', url=''):
    """ Given an account name or url, search the metadata dataframe to find the corresponding row entry 
        input: 
               account (str) [optional] account name if applicable
               url (str) [optional] url of the account if applicable
        output: nothing
    """
    metadata = pd.read_csv('accounts.txt', index_col=0).reset_index()
    if account is not '':
        try:
            rowindex = metadata.index[metadata['Account Name'] == account.lower()].tolist()[0]
        except IndexError:
            print("\nAccount not found.\n")
            return
    elif url is not '':
        try:
            rowindex = metadata.index[metadata['url'] == url.lower()].tolist()[0]
        except IndexError:
            print("\nurl not found.\n")
            return
    else:
        print("Account entry not found. Please try again")
        sys.exit(2)
    retrieve_password(rowindex+1)



def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:],'h')
    except getopt.GetoptError:
        print("Usage:  python3 manager.py")
        sys.exit(2)

    mpassword = ''

    for opt, arg in opts:
        if opt == '-h':
            print("Usage:  python3 manager.py")
            sys.exit(2)
        else: 
            print("Usage:  python3 manager.py")
            sys.exit(2)
    
    # check if the passwords file exists, it will exist if a master password has been established
    if not os.path.isfile('passwords.txt'): 
        create_master_password()
        sys.exit(2)

    # Prompt and verify master password
    mpassword = getpass.getpass("Please enter master password: \n")

    incorrect_counter = 0
    while(incorrect_counter < 10):
        if not verify_password(mpassword):
            print("Password incorrect.\n")

            mpassword = getpass.getpass("Please enter master password: ")
            print()

            incorrect_counter += 1

            # Too many failed attempts, delete password database. 
            if incorrect_counter == 9:
                os.remove('accounts.txt')
                os.remove('passwords.txt')
                print("Password database deleted.")
                sys.exit(2)
        else:
            # delete master password from memory 
            del mpassword 
            break

        if incorrect_counter > 5:
            print("Nearing maximum password attempts, deleting password database in  {} attempts.".format(9-incorrect_counter))

    # Main program with options
    while True:
        try:
            action = int(input("What would you like to do? \n1 - print accounts \n2 - retrieve account password \n3 - add account\n4 - delete password database\n5 - exit\n"))
        except ValueError:
            print("\nPlease choose a valid option between 1, 2, 3, 4, and 5.\n")
            continue

        # print accounts
        if action is 1: 
            metadata = pd.read_csv('accounts.txt', index_col=0).reset_index(drop=True)
            print()
            print(metadata)
            del metadata
            print()

        # retrieve account password
        elif action is 2:
            print("You have chosen to retrieve account information.\nPlease enter either an account name or url, or both.")
            account = input("Enter account name or press enter to enter url: ")
            url = input("Enter account url or press enter to proceed: ")
            if account == '' and url == '':
                print("Please enter either an account name or url, or both, to search an account entry.\n")
            else:
                search_entry(account=account, url=url)

        # add account
        elif action is 3:
            print("You have chosen to enter new account information.\nPlease enter either an account name or url, or both.")
            account = input("Enter account name or press enter to enter url: ")
            url = input("Enter account url or press enter to proceed: ")
            if account == '' and url == '':
                print("Please enter either an account name or url, or both, to create a new account entry.\n")
            else:
                add_entry(account=account, url=url)

        # delete database
        elif action is 4:
            mpassword = getpass.getpass("\nAre you sure you want to delete your password database? WARNING: This is permanent!\nEnter master password to delete, enter anything else to exit:")

            # verify master password
            if not verify_password(mpassword):
                print("Incorrect Password, safely exiting..")
                sys.exit(2)
            else:
                os.remove('accounts.txt')
                os.remove('passwords.txt')
                print("Password database deleted.")
                sys.exit(2)

        # exit
        elif action is 5:
            sys.exit(2)

        # invalid option
        else: 
            print("\nPlease choose a valid option between 1, 2, 3, 4, and 5.\n")

main()