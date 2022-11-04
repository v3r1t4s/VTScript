"""import of modules"""

import argparse

# SET PATH HERE
PATH = str(r"C:\Users\etc OR /home/etc")

if __name__ == '__main__':

    # Create the parser to have arguments in the script
    parser = argparse.ArgumentParser()

    # Adding SHA argument (let required True for now?)
    parser.add_argument('--SHA', type=str, required=True)

    # Parse the argument
    args = parser.parse_args()

    #  TESTING CODE OR NO ? (might be good for the user to see the HASH?)
    print("[+] You SHA is :" + args.SHA)

    class KeyLoading:
        """Class used to load key"""

        def __init__(self, key=""):
            self._key = key

        def get_key(self):
            """Getter function to load API key"""
            return self._key

        def set_api_key(self, file):
            """Read API Key from the file path provided in get_path()"""
            try:
                with open(file, "r", encoding="UTF-8") as api_file:
                    api_file = api_file.readline()
                    self._key = api_file
            except IOError:
                print("[-] Couldn't read the file!")

    API = KeyLoading()

    API.set_api_key(PATH)

    # TEST CODE FOR DISPLAYING API KEY
    if API.get_key():
        print("[+] Your API Key is: " + API.get_key())
