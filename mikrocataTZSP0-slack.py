#!/usr/bin/env python3

import ssl
import os
import socket
import re
from time import sleep
from datetime import datetime as dt
import pyinotify
import ujson
import json
import librouteros
from librouteros import connect
from librouteros.query import Key
import requests

USERNAME = "username"
PASSWORD = "password"
ROUTER_IP = "ip"
TIMEOUT = "1d"
USE_SSL = False
PORT = 8728
BLOCK_LIST_NAME = "suricata"

enable_telegram = True
TELEGRAM_TOKEN = "token"
TELEGRAM_CHATID = "id"

SLACK_ENABLE = False
SLACK_WEBHOOK = ""

WAN_IP = "pubip"
LOCAL_IP_PREFIX = "10.10."
WHITELIST_IPS = (WAN_IP, LOCAL_IP_PREFIX, "10.0.0.0/8", "1.1.1.1", "8.8.8.8", "8.8.4.4", "1.0.0.1", "9.9.9.9", "fe80:", "192.168.0.0/16, 172.16.1.0/24")
COMMENT_TIME_FORMAT = "%-d %b %Y %H:%M:%S.%f"
ENABLE_IPV6 = True
SEVERITY=("1","2")
ALLOW_SELF_SIGNED_CERTS = False
LISTEN_INTERFACE=("tzsp0")

SELKS_CONTAINER_DATA_SURICATA_LOG="/root/SELKS/docker/containers-data/suricata/logs/"
FILEPATH = os.path.abspath(SELKS_CONTAINER_DATA_SURICATA_LOG + "eve.json")

SAVE_LISTS = [BLOCK_LIST_NAME]

SAVE_LISTS_LOCATION = os.path.abspath("/var/lib/mikrocata/savelists-tzsp0.json")
SAVE_LISTS_LOCATION_V6 = os.path.abspath("/var/lib/mikrocata/savelists-tzsp0_v6.json")

UPTIME_BOOKMARK = os.path.abspath("/var/lib/mikrocata/uptime-tzsp0.bookmark")
IGNORE_LIST_LOCATION = os.path.abspath("/var/lib/mikrocata/ignore-tzsp0.conf")
ADD_ON_START = False

last_pos = 0
api = None
ignore_list = []
last_save_time = 0
SAVE_INTERVAL = 300

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        if event.pathname == FILEPATH:
            try:
                add_to_tik(read_json(FILEPATH))
            except ConnectionError:
                connect_to_tik()

    def process_IN_CREATE(self, event):
        if event.pathname == FILEPATH:
            print(f"[Mikrocata] New eve.json detected. Resetting last_pos.")
            global last_pos
            last_pos = 0
            self.process_IN_MODIFY(event)

    def process_IN_DELETE(self, event):
        if event.pathname == FILEPATH:
            print(f"[Mikrocata] eve.json deleted. Monitoring for new file.")

def seek_to_end(fpath):
    global last_pos

    if not ADD_ON_START:
        while True:
            try:
                last_pos = os.path.getsize(fpath)
                return

            except FileNotFoundError:
                print(f"[Mikrocata] File: {fpath} not found. Retrying in 10 seconds..")
                sleep(10)
                continue


def read_json(fpath):
    global last_pos
    while True:
        try:
            with open(fpath, "r") as f:
                f.seek(last_pos)
                alerts = []
                for line in f.readlines():
                    try:
                        alert = json.loads(line)
                        if alert.get('event_type') == 'alert':
                            alerts.append(json.loads(line))
                        else:
                            last_pos = f.tell()
                            continue
                    except:
                        continue
                last_pos = f.tell()
                return alerts
        except FileNotFoundError:
            print(f"[Mikrocata] File: {fpath} not found. Retrying in 10 seconds..")
            sleep(10)
            continue


def add_to_tik(alerts):
    global last_pos
    global api
    global last_save_time

    _address = Key("address")
    _id = Key(".id")
    _list = Key("list")

    address_list = api.path("/ip/firewall/address-list")
    address_list_v6 = api.path("/ipv6/firewall/address-list")
    resources = api.path("system/resource")

    for event in {item['src_ip']: item for item in alerts}.values():

        if str(event["alert"]["severity"]) not in SEVERITY:
            print("pass severity: " + str(event["alert"]["severity"]))
            break

        if str(event["in_iface"]) not in LISTEN_INTERFACE:
            break

        if not in_ignore_list(ignore_list, event):
            timestamp = dt.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime(COMMENT_TIME_FORMAT)
            is_v6 = ':' in event["src_ip"]
            curr_list = address_list_v6 if ENABLE_IPV6 and is_v6 else address_list

            if event["src_ip"].startswith(WHITELIST_IPS):
                if event["dest_ip"].startswith(WHITELIST_IPS):
                    continue
                wanted_ip, wanted_port = event["dest_ip"], event.get("src_port")
                src_ip, src_port = event["src_ip"], event.get("dest_port")
            else:
                wanted_ip, wanted_port = event["src_ip"], event.get("dest_port")
                src_ip, src_port = event["dest_ip"], event.get("src_port")

            try:
                cmnt = f"""[{event['alert']['gid']}:{event['alert']['signature_id']}] {event['alert']['signature']} ::: Port: {wanted_port}/{event['proto']} ::: timestamp: {timestamp}"""

                curr_list.add(list=BLOCK_LIST_NAME, address=wanted_ip, comment=cmnt, timeout=TIMEOUT)
                print(f"[Mikrocata] new ip added: {cmnt}")

                message = f"From: {wanted_ip}\nTo: {src_ip}:{wanted_port}\nRule: {cmnt}"
                if enable_telegram:
                    sendTelegram(message)
                sendSlack(message)

            except librouteros.exceptions.TrapError as e:
                if "failure: already have such entry" in str(e):
                    for row in curr_list.select(_id, _list, _address).where(_address == wanted_ip, _list == BLOCK_LIST_NAME):
                        curr_list.remove(row[".id"])
                    curr_list.add(list=BLOCK_LIST_NAME, address=wanted_ip, comment=cmnt, timeout=TIMEOUT)
                else:
                    raise
            except socket.timeout:
                connect_to_tik()

def check_tik_uptime(resources):

    for row in resources:
        uptime = row["uptime"]

    if "w" in uptime:
        weeks = int(re.search(r"(\A|\D)(\d*)w", uptime).group(2))
    else:
        weeks = 0

    if "d" in uptime:
        days = int(re.search(r"(\A|\D)(\d*)d", uptime).group(2))
    else:
        days = 0

    if "h" in uptime:
        hours = int(re.search(r"(\A|\D)(\d*)h", uptime).group(2))
    else:
        hours = 0

    if "m" in uptime:
        minutes = int(re.search(r"(\A|\D)(\d*)m", uptime).group(2))
    else:
        minutes = 0

    if "s" in uptime:
        seconds = int(re.search(r"(\A|\D)(\d*)s", uptime).group(2))
    else:
        seconds = 0

    total_seconds = (weeks*7*24 + days*24 + hours)*3600 + minutes*60 + seconds

    if total_seconds < 900:
        total_seconds = 900

    with open(UPTIME_BOOKMARK, "r") as f:
        try:
            bookmark = int(f.read())
        except ValueError:
            bookmark = 0

    with open(UPTIME_BOOKMARK, "w+") as f:
        f.write(str(total_seconds))

    if total_seconds < bookmark:
        return True

    return False


def connect_to_tik():
    global api


    actual_port = 8729 if USE_SSL else 8728

    while True:
        try:
            if USE_SSL:

                if ALLOW_SELF_SIGNED_CERTS:

                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers('DEFAULT@SECLEVEL=0')
                else:

                    ctx = ssl.create_default_context()
                    ctx.check_hostname = True
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    ctx.set_ciphers('DEFAULT@SECLEVEL=2')


                api = connect(username=USERNAME, password=PASSWORD, host=ROUTER_IP,
                            ssl_wrapper=ctx.wrap_socket, port=actual_port)
            else:

                api = connect(username=USERNAME, password=PASSWORD, host=ROUTER_IP,
                            port=actual_port)
            print(f"[Mikrocata] Connected to Mikrotik")
            break


        except librouteros.exceptions.TrapError as e:
            if "invalid user name or password" in str(e):
                print("[Mikrocata] Invalid username or password.")
                sleep(10)
                continue

            raise

        except socket.timeout as e:
            print(f"[Mikrocata] Socket timeout: {str(e)}.")
            sleep(30)
            continue

        except ConnectionRefusedError:
            print("[Mikrocata] Connection refused. (api-ssl disabled in router?)")
            sleep(10)
            continue

        except OSError as e:
            if e.errno == 113:
                print("[Mikrocata] No route to host. Retrying in 10 seconds..")
                sleep(10)
                continue

            if e.errno == 101:
                print("[Mikrocata] Network is unreachable. Retrying in 10 seconds..")
                sleep(10)
                continue

            raise

def save_lists(address_list,is_v6=False):
    _address = Key("address")
    _list = Key("list")
    _timeout = Key("timeout")
    _comment = Key("comment")
    curr_file = SAVE_LISTS_LOCATION
    if is_v6:
        curr_file = SAVE_LISTS_LOCATION_V6
    with open(curr_file, "w") as f:
        for save_list in SAVE_LISTS:
            for row in address_list.select(_list, _address, _timeout,
                                           _comment).where(_list == save_list):
                f.write(ujson.dumps(row) + "\n")

def add_saved_lists(address_list, is_v6=False):
    curr_file = SAVE_LISTS_LOCATION
    if is_v6:
        curr_file = SAVE_LISTS_LOCATION_V6
    with open(curr_file, "r") as f:
        addresses = [ujson.loads(line) for line in f.readlines()]
    for row in addresses:
        cmnt = row.get("comment")
        if cmnt is None:
            cmnt = ""
        try:
            address_list.add(list=row["list"], address=row["address"],
                             comment=cmnt, timeout=row["timeout"])

        except librouteros.exceptions.TrapError as e:
            if "failure: already have such entry" in str(e):
                continue

            raise

def read_ignore_list(fpath):
    global ignore_list

    try:
        with open(fpath, "r") as f:

            for line in f:
                line = line.partition("#")[0].strip()

                if line.strip():
                    ignore_list.append(line)

    except FileNotFoundError:
        print(f"[Mikrocata] File: {IGNORE_LIST_LOCATION} not found. Continuing..")

def in_ignore_list(ignr_list, event):
    for entry in ignr_list:
        if entry.isdigit() and int(entry) == int(event['alert']['signature_id']):
            sleep(1)
            return True

        if entry.startswith("re:"):
            entry = entry.partition("re:")[2].strip()

            if re.search(entry, event['alert']['signature']):
                sleep(1)
                return True

    return False

def sendTelegram(message):
    if enable_telegram:
        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage?chat_id={TELEGRAM_CHATID}&text={message}&disable_web_page_preview=true&parse_mode=html"
        try:
            response = requests.get(telegram_url)
            print(f"[Mikrocata] Telegram notification sent: {response.status_code}")
        except Exception as e:
            print(f"[Mikrocata] Failed to send Telegram message: {e}")

def sendSlack(message):
    if not SLACK_ENABLE or not SLACK_WEBHOOK:
        return
    try:
        payload = {"text": message}
        headers = {"Content-Type": "application/json"}
        response = requests.post(SLACK_WEBHOOK, data=json.dumps(payload), headers=headers)
        if response.status_code != 200:
            print(f"[Mikrocata] Slack notification failed: {response.text}")
    except Exception as e:
        print(f"[Mikrocata] Error sending Slack notification: {e}")

def main():
    seek_to_end(FILEPATH)
    connect_to_tik()
    read_ignore_list(IGNORE_LIST_LOCATION)
    os.makedirs(os.path.dirname(SAVE_LISTS_LOCATION), exist_ok=True)
    os.makedirs(os.path.dirname(SAVE_LISTS_LOCATION_V6), exist_ok=True)
    os.makedirs(os.path.dirname(UPTIME_BOOKMARK), exist_ok=True)

    directory_to_monitor = os.path.dirname(FILEPATH)

    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(directory_to_monitor, pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_DELETE, rec=False)

    while True:
        try:
            notifier.loop()

        except (librouteros.exceptions.ConnectionClosed, socket.timeout) as e:
            print(f"[Mikrocata] (4) {str(e)}")
            connect_to_tik()
            continue

        except librouteros.exceptions.TrapError as e:
            print(f"[Mikrocata] (8) librouteros.TrapError: {str(e)}")
            continue

        except KeyError as e:
            print(f"[Mikrocata] (8) KeyError: {str(e)}")
            continue

if __name__ == "__main__":
    main()
