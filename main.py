import os
import sys
import random
import string
import time
import inspect
import csv
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from getpass import getpass
import configparser
from colorama import Fore, Style
import pyperclip
from difflib import SequenceMatcher

script_path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

config_file = script_path + "/config.ini"
database_file = script_path + "/database.csv"

# If config file doesn't exist then create it
if not os.path.exists(config_file):
    f=open(config_file, "w")
    f.write("[auth]\n")
    f.write("masterPass = \n\n")
    f.write("[database]\n")
    f.write("location = " + database_file + "\n")
    f.close()

# Load Config File
config = configparser.ConfigParser()
config.read(config_file)
currentMasterPass = (config['auth']['masterpass'])
currentDatabaseLoc = (config['database']['location'])

# If database.csv doesn't exist then create it
if not os.path.exists(currentDatabaseLoc):
	with open(currentDatabaseLoc, mode='w') as password_database:
		fieldnames = ['url', 'username', 'password']
		writer = csv.DictWriter(password_database, fieldnames=fieldnames)
		writer.writeheader()


# Similarity calculation function
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

# The screen clear function
def screen_clear():
   # for mac and linux(here, os.name is 'posix')
   if os.name == 'posix':
      _ = os.system('clear')
   else:
      # for windows platfrom
      _ = os.system('cls')

# Main Menu
def mainMenu():
	print("\n\n /$$$$$$$                          /$$   /$$                           \n| $$__  $$                        | $$  /$$/                           \n| $$  \ $$/$$$$$$  /$$$$$$$/$$$$$$| $$ /$$/  /$$$$$$  /$$$$$$  /$$$$$$ \n| $$$$$$$|____  $$/$$_____/$$_____| $$$$$/  /$$__  $$/$$__  $$/$$__  $$\n| $$____/ /$$$$$$|  $$$$$|  $$$$$$| $$  $$ | $$$$$$$| $$$$$$$| $$  \ $$\n| $$     /$$__  $$\____  $\____  $| $$\  $$| $$_____| $$_____| $$  | $$\n| $$    |  $$$$$$$/$$$$$$$/$$$$$$$| $$ \  $|  $$$$$$|  $$$$$$| $$$$$$$/\n|__/     \_______|_______|_______/|__/  \__/\_______/\_______| $$____/ \n                                                             | $$      \n                                                             | $$      \n                                                             |__/      \n\n")
	print("		############## Main Menu #################\n 		##########################################")
	print("		##					##\n 		##	[1] Search for a Password 	##\n 		##					##\n 		##	[2] Add a Password 		##\n 		##					##\n 		##	[3] Run the PassKeep setup 	##\n 		##					##\n 		##	[CTL-C] Exit Anytime	 	##\n 		##					##\n 		##########################################\n 		##########################################")
	menuOption = input("\nEnter you option: ")

	if menuOption == '1':
		screen_clear()
		passSearch()

	elif menuOption == '2':
		screen_clear()
		passAdd()

	elif menuOption == '3':
		screen_clear()
		passSetup()

#Password Search
################
def passSearch():
	print("Password Search...")

	password_provided = getpass("Enter Master Password: ")  # This is input in the form of a string
	password = password_provided.encode()  # Convert to type bytes
	salt = b'56g3yurv939birv493v'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
	kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt,
	    iterations=100000,
	    backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

	cipher_suite = Fernet(key)

	try:
		masterPassTest = cipher_suite.decrypt(currentMasterPass.encode()).decode('ascii')

		print(Fore.GREEN + "Password Correct!" + Fore.WHITE)

		url = input("Enter  URL: ")

		with open(currentDatabaseLoc, mode='r') as password_database:
			password_reader = csv.reader(password_database, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

			for row in password_reader:
				database_url = row[0]
				# Search accuracy by ratio
				# print(database_url + ": " + similar(url, database_url))

				if similar(url, database_url) > 0.6 or url in database_url:
					cipher_username = row[1].encode()
					cipher_password = row[2].encode()

					plain_url = row[0]
					plain_username = cipher_suite.decrypt(cipher_username).decode()
					plain_password = cipher_suite.decrypt(cipher_password).decode()

					pyperclip.copy(plain_password)

					print("\n############################################\n# Login Credencials for " + plain_url + "\n############################################")
					print("[-] Website: " + plain_url + "\n[-] Username: " + plain_username + "\n[-] New Password: " + plain_password + "\n############################################\n")
					print(Fore.GREEN + "[+] Password copied to clipboard\n" + Fore.WHITE)

		input("Press any key to coninue...")
		screen_clear()
			
		mainMenu()

	except InvalidToken as e:
		print(Fore.RED + "Error: Incorrect Password - please try again!" + Fore.WHITE)
		time.sleep(2)
		mainMenu()


#Password Add
#############
def passAdd():
	print("Password Add...")

	password_provided = getpass("Enter Master Password: ")  # This is input in the form of a string
	password = password_provided.encode()  # Convert to type bytes
	salt = b'56g3yurv939birv493v'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
	kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt,
	    iterations=100000,
	    backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

	cipher_suite = Fernet(key)

	try:
		masterPassTest = cipher_suite.decrypt(currentMasterPass.encode()).decode('ascii')

		print(Fore.GREEN + "Password Correct!" + Fore.WHITE)

		url = input("Enter URL: ")
		username = input("Enter Username/Email: ")

		newpass = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation) for _ in range(20))
		pyperclip.copy(newpass)

		print("############################################\n# Login Credencials for " + url + "\n############################################")
		print("[-] Website: " + url + "\n[-] Username: " + username + "\n[-] New Password: " + newpass + "\n############################################\n")
		print(Fore.GREEN + "[+] Password copied to clipboard\n" + Fore.WHITE)

		print("Saving your password to the database...")

		cipher_username = cipher_suite.encrypt(username.encode())
		plain_username = cipher_suite.decrypt(cipher_username)

		cipher_newpass = cipher_suite.encrypt(newpass.encode())
		plain_pass = cipher_suite.decrypt(cipher_newpass)

		with open(currentDatabaseLoc, mode='a') as password_database:
			password_writer = csv.writer(password_database, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

			password_writer.writerow([url, cipher_username.decode(), cipher_newpass.decode()])

		print("Credencials saved!")
		input("Press enter to continue...")
		screen_clear()

		mainMenu()


	except InvalidToken as e:
		print(Fore.RED + "Error: Incorrect Password - please try again!" + Fore.WHITE)
		time.sleep(2)
		screen_clear()

		mainMenu()

#PassKeep Setup
###############
def passSetup():

	# Load Menu
	print("Running setup...")
	time.sleep(.5)
	screen_clear()
	print("\n############## Setup Menu ################\n##########################################")
	print("##					##\n##	[1] Set Master Password 	##\n##					##\n##	[2] Choose database location 	##\n##					##\n##	[0] Main Menu 			##\n##					##\n##########################################\n##########################################")

	menuOption = input("\nEnter you option: ")

	# Set Master Password
	def setMasterPass():

# 		password_provided = getpass("Enter Master Password: ")  # This is input in the form of a string
# 		password = password_provided.encode()  # Convert to type bytes
# 		salt = b'56g3yurv939birv493v'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
# 		kdf = PBKDF2HMAC(
# 		    algorithm=hashes.SHA256(),
# 		    length=32,
# 		    salt=salt,
# 		    iterations=100000,
# 		    backend=default_backend()
# 		)

# 		key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

# 		cipher_suite = Fernet(key)

# 		try:
# 			masterPassTest = cipher_suite.decrypt(currentMasterPass.encode()).decode('ascii')

# 			with open(currentDatabaseLoc, mode='r') as password_database:
# 				password_reader = csv.reader(password_database, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

# 				for row in password_reader:
# 					encrypted_username = row[1]
# 					encrypted_password = row[2]
# 					username = cipher_suite.decrypt(encrypted_username.encode())
# 					password = cipher_suite.decrypt(encrypted_password.encode())

# 					print(Fore.GREEN + "Password Correct!" + Fore.WHITE)

# 					print(username)
# 					print(password)

# 		except InvalidToken as e:
# 			print(Fore.RED + "Error: Incorrect Password - please try again!" + Fore.WHITE)
# 			time.sleep(2)
# 			mainMenu()


# 		except InvalidToken as e:
# 			print(Fore.RED + "Error: Incorrect Password - please try again!" + Fore.WHITE)
# 			time.sleep(2)
# 			passSetup()

		masterPass1 = getpass("Enter New Master Password: ")
		masterPass2 = getpass("Re-Enter New Master Password: ")

		if masterPass1 == masterPass2:

			# Create MasterKey
			password_provided = masterPass1  # This is input in the form of a string
			password = password_provided.encode()  # Convert to type bytes
			salt = b'56g3yurv939birv493v'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
			kdf = PBKDF2HMAC(
			    algorithm=hashes.SHA256(),
			    length=32,
			    salt=salt,
			    iterations=100000,
			    backend=default_backend()
			)

			key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

			cipher_suite = Fernet(key)

			correct = "Password Corrent!".encode()

			cipher_correct = cipher_suite.encrypt(correct).decode('ascii')

			# Parse Masterkey to config file
			config['auth'] = {'masterPass':cipher_correct}
			with open(config_file, 'w') as configfile:
				config.write(configfile)


			print(Fore.GREEN + "Master Password Set!" + Fore.WHITE)
			time.sleep(2)

			screen_clear()
			passSetup()

		else:
			input("Error: Passwords do not match. Press any key and try again...")
			screen_clear()
			passSetup()

	def setDatabaseLocation():
		new_location = input("Enter database location (Leave empyty to keep " + currentDatabaseLoc + "): ") or currentDatabaseLoc
		# Parse Masterkey to config file
		config['database'] = {'location':new_location}
		with open(config_file, 'w') as configfile:
			config.write(configfile)

		print(Fore.GREEN + "Database location Set!" + Fore.WHITE)
		time.sleep(2)

		screen_clear()
		passSetup()

	if menuOption == '1':
		print("Master Password Setup...")
		time.sleep(1)
		setMasterPass()

	elif menuOption == '2':
		print("Database Location Setup...")
		time.sleep(1)
		setDatabaseLocation()

	elif menuOption == '0':
		screen_clear()
		print("Returning to main menu...")
		time.sleep(1)
		screen_clear()
		mainMenu()

try:
	screen_clear()
	mainMenu()
except KeyboardInterrupt:
	print("")