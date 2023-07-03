#!/usr/bin/env python3

# This script is supposed to be executed directly and NOT via the event-action command!

# Written by Benjamin Eggerstedt in 2023
# Developed during my free time, thus not official ALE code.

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

#
# Imports
#
import sys
try:
    import requests
except ImportError as ie:
    print(ie)
    # python3 -m pip install requests
    sys.exit("Please install python-requests!")
import json
try:
    import urllib3
except ImportError as ie:
    print(ie)
    # This comes as dependency of requests, so should always be there.
    # python3 -m pip install urllib3
    sys.exit("Please install urllib3!")  
import time

if __name__ == "__main__":
    # Load settings from settings.json file
    print("[+] Reading settings.json file")
    try:
# Depending on the target platform to run/host this script you may need to modify this
#        with open("/flash/python/settings.json", "r") as json_data:
        with open("settings.json", "r") as json_data:
            settings = json.load(json_data)
            ov_hostname = settings["ov_hostname"]
            ov_username = settings["ov_username"]
            ov_password = settings["ov_password"]
            validate_https_certificate = settings["validate_https_certificate"]
            email_from = settings["email_from"]
            send_emails = settings["send_emails"]
            runs_on_omniswitch = settings["runs_on_omniswitch"]
            smtp_server = settings["smtp_server"]
            smtp_auth = settings["smtp_auth"]
            smtp_user = settings["smtp_user"]
            smtp_port = settings["smtp_port"]
            smtp_password = settings["smtp_password"]
            language = settings["language"]
            # Note that email_to will override to sys.argv[2] if given
            email_to = settings["email_to"]
    except IOError as ioe:
        print(ioe)
        sys.exit("ERROR: Couldn't find/open settings.json file!")
    except TypeError as te:
        print(te)
        sys.exit("ERROR: Couldn't read json format!")

    # Validate that setting.json is configured and not using the default
    if ov_hostname == "omnivista.example.com":
        sys.exit("ERROR: Can't work with default template value for OmniVista hostname!")

    # Validate that the hostname is a hostname, not URL
    if "https://" in ov_hostname:
        print("[!] Found \"https://\" in ov_hostname, removing it!")
        ov_hostname = ov_hostname.lstrip("https://")

    # Validate that the hostname doesn't contain a "/"
    if "/" in ov_hostname:
        print("[!] Found \"/\" in hostname, removing it!")
        ov_hostname = ov_hostname.strip("/")

    # Figure out if HTTPS certificates should be validated
    # That should actually be the default, so we'll warn if disabled.

    if(validate_https_certificate.lower() == "yes"):
        check_certs = True
    else:
        # This is needed to get rid of a warning coming from urllib3 on self-signed certificates
        print("[!] Ignoring certificate warnings or self-signed certificates!")
        print("[!] You should really fix this!")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        check_certs = False    

    # We support to send the guest_account details via email to the account creator
    # if len(sys.argv) == 2:
    #     print(f"[+] Updating email_to address to: {sys.argv[1]}")
    #     email_to = sys.argv[1]

    # Test connection to OmniVista
    print(f"[*] Attempting to connect to OmniVista server @ https://{ov_hostname}")

    req = requests.Session()

    # Use the ca-certificate store managed via Debian
    # This is just for development, should be commented out for production.
    #req.verify = "/etc/ssl/certs/"

    # Check if we die on the HTTPS certificate
    try:
        ov = req.get(f"https://{ov_hostname}", verify=check_certs)
    except requests.exceptions.SSLError as sslerror:
        print(sslerror)
        sys.exit("[!] Caught issues on certificate, try to change \"validate_https_certificate\" to \"no\" in settings.json. Exiting!")

    if ov.status_code == 200:
        print(f"[*] Connection to {ov_hostname} successful!")
    else:
        sys.exit(f"[!] Connection to {ov_hostname} failed, exiting!")

    ov_login_data = {"userName" : ov_username, "password" : ov_password}
    ov_header = {"Content-Type": "application/json"}

    # requests.post with json=payload was introduced in version 2.4.2
    # otherwise it would need to be "data=json.dumps(ov_login_data),"

    ov = req.post(f"https://{ov_hostname}/rest-api/login",
                headers=ov_header,
                json=ov_login_data,
                verify=check_certs)

    if ov.status_code == 200:
        ov_header["Authorization"] = f"Bearer {ov.json()['accessToken']}"
    else:
        sys.exit("[!] The connection to OmniVista was not successful! Exiting!")
    
    devices_resp = req.get(f"https://{ov_hostname}/api/devices?fieldSetName=discovery",
                headers=ov_header,
                verify=check_certs)
    
    print(f"[*] Number of devices managed by this OmniVista 2500: {len(devices_resp.json()['response'])}")

    print(json.dumps(devices_resp.json()['response'], indent=4))

    # Logout from API
    ov3 = req.get(f"https://{ov_hostname}/rest-api/logout", verify=check_certs)
