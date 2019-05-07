# PasswordManager
A secure password manager that runs locally on your computer through a command line interface. 

## Installation
Run the following command to install all the required packages, runs in python3

    pip3 install -r requriements.txt

## Usage
On startup, run the following command:

    python3 manager.py

On subsequent runs, run the following command:

    python3 manager.py -p [masterpassword]

To delete the password database, run the following command:

    python3 manager.py -d

Caution - deleting the password database is irreversible and permanent. 