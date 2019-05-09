# PasswordManager
A secure password manager that runs locally on your computer though a command line interface. 

## Installation
Run the following command to install all the required packages, runs in python3

    pip3 install -r requriements.txt

## Usage
On startup, run the following command:

    python3 manager.py

On subsequent runs, run the following command and user will be prompted for master password:

    python3 manager.py -p

To delete the password database, run the following command:

    python3 manager.py -d

Caution - deleting the password database is irreversible and permanent. 
        - There is a maximum allowance of 10 erroneous password attempts. After 10 attempts, the password database will be deleted. 

## Command Line Interface
1. print accounts 

    This option will print out the database in table format displaying all the account names and urls.

2. retrieve account password 

    This option will prompt the user to retrieve an account password based on an account name or url, both. The associated password will be copied to the user's clipboard.

3. add account

    This option will prompt the user to add an account password based on an account name or url, or both. A strong, secure password will be generated, stored, and then copied to the user's clipboard.

4. exit

    This option will exit the application.