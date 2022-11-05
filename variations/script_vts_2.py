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
    print("[+] You SHA is :" + args.SHA)

    # Might recode or put a helper function just before to list path when hitting tab...
    def input_path(prompt):
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

    PATH = ""

    PATH = (input_path(PATH))

    class KeyLoading:
        """Class used to load key"""

        def __init__(self, key=""):
            self._key = key

        def get_key(self):
            """Getter function to load API key"""
            return self._key

        def set_key(self, file):
            """Read API Key from the file path provided in get_path()"""
            try:
                with open(file, "r", encoding="UTF-8") as api_file:
                    api_file = api_file.readline()

                self._key = api_file
            except IOError:
                print("[-] Couldn't read the file!")

    API = KeyLoading()

    API.set_key(PATH)

    # TEST CODE FOR DISPLAYING API KEY
    print("Your API key is: " + API.get_key())
