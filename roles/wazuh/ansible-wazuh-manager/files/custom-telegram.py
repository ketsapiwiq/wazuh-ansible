#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install it by executing: /var/ossec/framework/python/bin/pip3 install requests")
    sys.exit(1)

# Global variables
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    alert_file_location = args[1]
    manager_name = os.path.basename(alert_file_location)
    # Read args
    alert_json = open(alert_file_location)
    json_alert = json.load(alert_json)
    alert_json.close()

    debug("# Starting")
    # Request Telegram API
    debug("# Getting alert")
    alert = json_alert['rule']['description']

    debug("# Creating message")
    msg = "Wazuh alert" + "\n" + alert

    debug("# Getting custom hook_url")
    hook_url = json_alert['integration']['hook_url']

    debug("# Getting custom chat_id")
    chat_id = json_alert['integration']['chat_id']

    debug("# Sending message")
    send_msg(msg, hook_url, chat_id)

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()

def send_msg(msg, hook_url, chat_id):
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

    # requests lib
    url = hook_url+"?chat_id="+chat_id+"&text="+msg+"&parse_mode=HTML"
    res = requests.post(url, headers=headers)

    debug(str(res))

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 2:
            msg = '{0} {1} {2}'.format(now, sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else '')
            debug_enabled = (len(sys.argv) > 2 and sys.argv[2] == 'debug')
        else:
            bad_arguments = True

        if bad_arguments:
            print("Wrong arguments")
            print("Usage: {0} alert_file json_parameters [debug]".format(sys.argv[0]))
            raise ValueError("Wrong arguments")

        # Main function
        main(sys.argv)

    except Exception as e:
        print(e)
