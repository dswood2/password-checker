import requests
import hashlib
import sys
import getpass
import re

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url, headers={'Add-Padding': 'True'})
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check and int(count) > 0:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def password_strength_check(password):
    if len(password) < 8:
        return "Password should be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password should contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password should contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return "Password should contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password should contain at least one special character."
    return "Password is strong."

def main():
    while True:
        print("Choose an option:")
        print("1. Check passwords from a file (checkList.txt)")
        print("2. Enter passwords manually")
        print("3. Check password strength")
        print("4. Quit")
        choice = input("Enter your choice (1/2/3/4): ")

        if choice == '1':
            try:
                with open('checkList.txt') as file:
                    for password in file.readlines():
                        password = password.strip()
                        count = pwned_api_check(password)
                        if count:
                            print(f'{password} was found {count} times. You should change your password.')
                        else:
                            print(f'{password} was NOT found.')
                print("All done.")
            except FileNotFoundError:
                print("File 'checkList.txt' not found.")

        elif choice == '2':
            while True:
                password = input("Enter a password (or press Enter to go back to menu): ")
                if password == '':
                    break
                count = pwned_api_check(password.strip())
                if count:
                    print(f'{password} was found {count} times. You should change your password.')
                else:
                    print(f'{password} was NOT found.')

        elif choice == '3':
            while True:
                password = input("Enter a password to check its strength (or press Enter to go back to menu): ")
                if password == '':
                    break
                strength_message = password_strength_check(password)
                print(strength_message)

        elif choice == '4':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    sys.exit(main())