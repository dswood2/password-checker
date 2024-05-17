# Password Checker

The Password Checker is a Python script that allows you to check if your passwords have been compromised in any known data breaches. It utilizes the Have I Been Pwned API to securely check your passwords against a large database of compromised credentials. Additionally, it provides a password strength evaluation feature to assess the strength of your passwords.

## Features

- Check passwords from a file (`checkList.txt`) or enter them manually
- Securely checks passwords without sending them over the network
- Provides feedback on the number of times a password has been compromised
- Offers password strength evaluation based on common strength criteria

## Prerequisites

- Python 3.x
- `requests` library (can be installed via `pip install requests`)

## Usage

1. Clone the repository or download the `password_checker.py` file.

2. (Optional) Create a file named `checkList.txt` in the same directory as the script and enter the passwords you want to check, one per line.

3. Run the script using the following command:
  - python password_checker.py

4. Choose an option from the menu:
  - Option 1: Check passwords from the `checkList.txt` file
  - Option 2: Enter passwords manually
  - Option 3: Check password strength
  - Option 4: Quit the program

5. If you choose option 1, the script will read the passwords from the `checkList.txt` file and check each password against the Have I Been Pwned API. It will display the results indicating if the password has been compromised and the number of times it was found in breaches.

6. If you choose option 2, you can manually enter passwords one by one. After entering each password, the script will check it against the API and display the result. To finish entering passwords, simply press Enter without typing a password.

7. If you choose option 3, you can enter passwords to evaluate their strength. The script will assess the password based on criteria such as length, presence of uppercase and lowercase letters, digits, and special characters. It will provide feedback on the strength of the password.

8. Option 4 will exit the program.

## How It Works

The Password Checker uses the Have I Been Pwned API to check if a password has been compromised in any known data breaches. It follows these steps:

1. The script takes a password as input (either from a file or manually entered).

2. It generates a SHA-1 hash of the password.

3. The first five characters of the hash are sent to the API, which responds with a list of hash suffixes that match the partial hash.

4. The script compares the full hash of the password with the returned hash suffixes to determine if the password has been compromised.

5. If a match is found, the script reports the number of times the password has been compromised. If no match is found, it indicates that the password has not been compromised.

This approach ensures that the actual password is never sent over the network, providing a secure way to check the password's compromise status.

For the password strength evaluation, the script checks the password against various criteria, such as minimum length, presence of uppercase and lowercase letters, digits, and special characters. It provides feedback on the strength of the password based on these criteria.

## Disclaimer

This password checker is intended for educational and informational purposes only. It relies on the Have I Been Pwned API and the accuracy of its database. While it can provide insights into the compromise status of passwords and evaluate their strength, it should not be solely relied upon for ensuring password security.

Always use strong, unique passwords and enable two-factor authentication whenever possible. Regularly updating your passwords and monitoring for any suspicious activity on your accounts is crucial for maintaining online security.
