"""import of modules"""

import argparse
import os
import sys
from pathlib import Path

if __name__ == '__main__':

    # Create the parser to have arguments in the script
    parser = argparse.ArgumentParser()

    # Adding SHA argument (let required True for now?)
    parser.add_argument('--SHA', type=str, required=True)

    # Parse the argument
    args = parser.parse_args()

    #  TESTING CODE OR NO ? (might be good for the user to see the HASH?)
    print("[+] Your SHA is: " + args.SHA)

    # Sys.exit is good for handling error ? While loop until good result might be an option too...
    # Might recode or put a helper function just before to list path when hitting tab...
    def get_path(prompt):
        """Get Path with input(), check if both path/file exist"""

        try:
            res = input("Please input an absolute path: " + prompt)
            if os.path.exists(res):
                print("[+] The path is valid!")
                res = Path(res)

                if res.is_file():
                    print("[+] We did find the file!")
                else:
                    print("[-] We didn't found the file!")
                    sys.exit(1)
            else:
                print("[-] The path is not valid!")
                sys.exit(1)
        except ValueError:
            sys.exit(1)

        return res

    STRING = ""

    path = get_path(STRING)

    def read_api_key(file):
        """Read API Key from the file path provided in get_path()"""

        try:
            with open(file, "r", encoding="UTF-8") as api_file:
                return api_file.readline()
        except IOError:
            print("[-] Couldn't read the file!")

    api_key = read_api_key(path)

    # TEST CODE FOR DISPLAYING API KEY
    print("[+] Your API key is: " + api_key)
