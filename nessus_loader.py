## Nessus Case Downloader
# 
# Downloads and stores Nessus report data in the local folder. A SQLite DB is created to store login credentials!
# Works only with API Keys for now!


## Imports
import os
import time
import sqlite3
import requests
import json
import io
from nessrest import ness6rest

## Functions

def clear():
    # Clears the screen entirely
    os.system("cls")
    return

def user_prompt():
    # Standard user input
    prompt = input("nessusloader >> ")
    return prompt

def sql_string_cleanup(string):
    # Takes a given SQL string and returns it clean
    try:
        string2 = str(string)
        string3 = string2.replace("(\'", "")
        string4 = string3.replace("\',)", "")
        return string4
    except:
        print("Error formatting the SQLite string... Please retry!")
        time.sleep(2)

def profile_create():
    # Creates a table in the given SQLite DB
    try:  
        connect = sqlite3.connect("credentials.db")
        cursor = connect.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS profiles (
                        name TEXT PRIMARY KEY,
                        url TEXT,
                        port TEXT,
                        akey TEXT,
                        skey TEXT);""")
        connect.commit()
        connect.close()
        return True
    except:
        print("Error creating profile...")
        time.sleep(2)
        return False

def profile_delete(profile_name):
    # Deletes a table in given database
    try:
        connect = sqlite3.connect("credentials.db")
        cursor = connect.cursor()
        cursor.execute("""DELETE FROM profiles WHERE name = '%s'""" % profile_name)
        connect.commit()
        connect.close()
    except:
        print("Profile not existing")
        time.sleep(2)
    
def profile_show_existing():
    # Parses the given SQL File for tables and returns a clean list of tablenames
    try:
        connect = sqlite3.connect("credentials.db")
        cursor = connect.cursor()
        cursor.execute("SELECT * FROM profiles")
        contents = []
        for row in cursor:
            name = row[0]
            string = sql_string_cleanup(name)
            contents.append(string)
        connect.close()
        return contents
    except:
        print("Error listing the errors from database... Please retry!")

def profile_load(profile_name):
    # Selects a given logincredential and returns a dictionary 
    try:
        connect = sqlite3.connect("credentials.db")
        cursor = connect.cursor()
        
        cursor.execute("SELECT * FROM profiles WHERE name='%s'"  % profile_name)
        row = cursor.fetchone()
        name = row[0]
        url = row[1]
        port = row[2]
        akey = row[3]
        skey = row[4]
        profile= {"name": name, "url": url, "port": port, "akey": akey, "skey": skey}
        connect.close()
        return profile
    except:
        print("Error loading profile from database... Please retry!")
        time.sleep(2)
        return

def save_profile(profile):
    # Saves a given dictionary in SQLite DB
    try:
        connect = sqlite3.connect("credentials.db")
        cursor = connect.cursor()
        liste = []
        liste.append(profile["name"])
        liste.append(profile["url"])
        liste.append(profile["port"])
        liste.append(profile["akey"])
        liste.append(profile["skey"])
        cursor.execute("""INSERT INTO profiles VALUES (?,?,?,?,?)""", liste)
        connect.commit()
        connect.close()
        return
    except:
        print("Error saving profile to database... Please retry!")
        time.sleep(2)
        return

def print_header():
    # Prints the header
    print("### Nessus Loader v. 0.1 ###\n")
    return

def print_state(profile, loaded):
    # Prints connection state
    if loaded == True:
        print("# Connection: %s loaded\n" % profile["name"])
    else:
        print("# Connection: No profile loaded\n")

def print_main_menu(loaded):
    # Prints the main menu
    if loaded == True:
        print("[1] - Show existing folders and IDs")
        print("[2] - Change connection profile")
        print("[3] - Show details for loaded connection")
        
        print("[0] - Exit Nessusloader\n")
    else:
        print("[1] - Show and load existing connection profiles")
        print("[2] - Create new connection profile")
        print("[3] - Delete existing connection profiles\n")
        print("[0] - Exit Nessusloader\n")

def print_load_tables():
    # Prints all existing tables from given SQLite DB and lets the user choose one
    freeze = True
    while freeze == True:
        clear()
        contents = profile_show_existing()
        print_header()
        print("\n### Existing profiles in this database ###\n")
        count = 1
        for i in contents:
            print("["+str(count)+"] - " + str(i))
            count += 1
        print("\n")
        print("[0] - Back to menu\n")
        menu = user_prompt()
        if menu == "0":
            freeze = False
            return {"loaded": False, "profile_name": "", "profile": {}}
        else:
            profile_name = str(contents[int(menu)-1])
            try:
                profile = profile_load(profile_name)
                print("Profile successfully loaded")
                time.sleep(1)
                loaded = {"loaded": True, "profile_name": str(profile_name), "profile": profile}
                return loaded
            except:
                print("Error loading profile... retry!")
                time.sleep(2)
                loaded = {"loaded": False, "profile_name": "", "profile": {}}
                return loaded

def print_delete_tables():
    # Prints all existing tables from given SQLite DB and lets the user choose one
    freeze = True
    while freeze == True:
        clear()
        contents = profile_show_existing()
        print_header()
        print("\n### Existing profiles in this database ###\n")
        count = 1
        for i in contents:
            print("["+str(count)+"] - " + str(i))
            count += 1
        print("\n")
        print("[0] - Back to menu\n")
        menu = user_prompt()
        if menu == "0":
            freeze = False
            return {"loaded": False, "profile_name": "", "profile": {}}
        else:
            profile_name = str(contents[int(menu)-1])
            try:
                profile = profile_delete(profile_name)
                print("Profile successfully deleted")
                time.sleep(1)
                return 
            except:
                print("Error loading profile... retry!")
                time.sleep(2)
                return 

def print_details_connection(profile):
    freeze = True
    while freeze == True:
        name = profile["name"]
        url = "https://"+str(profile["url"])+":"+str(profile["port"])
        akey = profile["akey"]
        skey = profile["skey"]
        clear()
        print_header()
        print("\nThe currently loaded connection: \n")
        print("Name - " + name)
        print("URL - " + url)
        print("AccessKey - " + akey)
        print("SecretKey - " + skey)
        print("\n")
        print("[0] - Back to main menu\n")
        menu = user_prompt()
        if menu == "0":
            freeze = False
        else:
            print("Invalid entry, please retry!")
            time.sleep(1)
        
def print_existing_folders(profile):
    # Prints out the existing scan folders of the connected Nessus API
    freeze = True
    while freeze == True:
        try:
            url = "https://"+str(profile["url"])+":"+str(profile["port"])
            headers = {'Content-type': 'application/json', 'X-ApiKeys': 'accessKey='+profile["akey"]+'; secretKey='+profile["skey"]} 
            requests.packages.urllib3.disable_warnings() 
            folders = requests.get(url +'/scans', headers = headers, verify = False)
            folders2 = folders.json()
            folders3 = folders2["folders"]
            print("\n")
            counter = 1
            for i in folders3:
                print("[" + str(counter) + "] - " + str(i["id"])+ ": " +str(i["name"]))
                counter += 1
            print("\n")
            print("[0] - Back to menu\n")
            menu = user_prompt()
            dbpasswd = ""
            if menu == "0":
                freeze = False
            else:
                print("\nPlease enter the format [nessus, csv, html, db]:")
                print("(Please be aware, that 'db' format is still not working properly...)\n")
                user_format = str(user_prompt())
                if user_format == "db":
                    print("\nPlease enter a password for encryption: \n")
                    dbpasswd = user_prompt()
                    print("\n")
                try:
                    download_files(profile, folders3[int(menu)-1]["id"], user_format, dbpasswd)
                except:
                    print("Error downloading the file...")
                    time.sleep(2)
                return 
        except:
            print("Error listing the folders... Please retry or check your profile")
            time.sleep(2)
            return

def download_files(profile, dl_id, user_format, dbpasswd=""):
    # Downloader, props to Nessrest :)
    nessus_url = "https://" + profile["url"] +  ":" + profile["port"]
    insecure = True
    scanner = ness6rest.Scanner(url=nessus_url, api_akey=profile["akey"], api_skey=profile["skey"], insecure=insecure, ca_bundle=None)
    if scanner:
        scanner.action(action='scans', method='get')
        folders = scanner.res['folders']
        scans = scanner.res['scans']
        folders_id = []
        for i in folders: 
            if str(i['id']) == str(dl_id):
                folders_id.append(i)
        for f in folders_id:
            if not os.path.exists(f['name']):
                os.mkdir(f['name'])
        for i in folders_id:
            for s in scans:
                if s['folder_id'] == i['id']:
                    scanner.scan_name = s['name']
                    scanner.scan_id = s['id']
                    folder_name = i['name']
                    folder_type = i['type']
                    if folder_type == 'trash' :
                        continue
                    if s['status'] == 'completed':
                        file_name = '%s_%s.%s' % (scanner.scan_name, scanner.scan_id, user_format)
                        file_name = file_name.replace('\\','_')
                        file_name = file_name.replace('/','_')
                        file_name = file_name.strip()
                        relative_path_name = folder_name + '/' + file_name
                        # PDF not yet supported
                        with io.open(relative_path_name,'wt') as fp:
                            fp.write(str(scanner.download_scan(export_format=user_format, dbpasswd=dbpasswd)))

def print_create_profile():
    # Prints a menu to create a table
    freeze = True
    while freeze == True:
        clear()
        print_header()
        print("\nPlease enter a name for your profile: \n")
        profile_name = user_prompt()
        profile_create()
        print("\nPlease enter an url: \n")
        url = user_prompt()
        print("\nPlease enter a port: \n")
        port = user_prompt()
        print("\nPlease enter the accesskey: \n")
        akey = user_prompt()
        print("\nPlease enter the secretkey: \n")
        skey = user_prompt()
        profile_dict = {"name": profile_name, "url": url, "port": port, "akey": akey, "skey": skey}
        save_profile(profile_dict)
        print("Case successfully created!")
        time.sleep(1)
        return {"loaded": True, "profile_name": profile_name, "profile": profile_dict}

def main():
    # Main
    program_active = True
    loaded = False
    profile = {}
    while program_active == True:
        clear()
        print_header()
        print("Welcome to Nessusloader...\n")
        print_state(profile, loaded)
        print_main_menu(loaded)
        menu = user_prompt()
        if loaded == False:
            if menu == "1":
                result = print_load_tables()
                loaded = result["loaded"]
                profile = result["profile"]
                profile_name = result["profile_name"]
            elif menu == "2":
                result = print_create_profile()
                loaded = result["loaded"]
                profile = result["profile"]
                profile_name = result["profile_name"]
            elif menu == "3":
                print_delete_tables()
            elif menu == "0":
                program_active = False
            else:
                print("Invalid, retry!")
                time.sleep(1)
        elif loaded == True:
            if menu == "1": 
                print_existing_folders(profile)
            
            elif menu == "2":
                loaded = False
                profile = {}
                profile_name = ""

            elif menu == "3":
                print_details_connection(profile)
            elif menu == "0":
                program_active = False
            else:
                print("Invalid, retry!")
                time.sleep(1)

####
if __name__ == '__main__':    
    main()
