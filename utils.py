#!/usr/bin/python
import argparse
import json
import re
import readline
import requests
import sys
import time

cmdlist  = ["exit", "help", "dump_old", "dump_new", "postgresqli", "mysqli", "mssqli", "nosqli", "mutation", "edges", "node", "$regex", "$ne", "__schema"]

def auto_completer(text, state):
    options = [x for x in cmdlist if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None


def jq(data):
    return json.dumps(data, indent=4, sort_keys=True)


REQUESTER_SESSION = None


def requester_session(sess=None):
    global REQUESTER_SESSION
    REQUESTER_SESSION = sess or requests.Session()
    return REQUESTER_SESSION


def requester(URL, method, payload):
    global REQUESTER_SESSION
    sess = REQUESTER_SESSION or requests

    if method == "POST":
        headers = {
            "content-type": "application/json",
        }
        json = {
            "query": payload,
        }
        r = sess.post(URL, headers=headers, json=json, verify="burp.crt")
        if not (200 <= r.status_code < 400):
            print("\033[91m/!\ API didn't respond correctly to a POST method !\033[0m")
            print(f"\033[91m/!\ API responded {r.status_code} to POST {URL}!\033[0m")
            print(r.headers)
            print(r.text)
            return None
    else:
        r = sess.get( URL+"?query={}".format(payload), verify="burp.crt")
    return r


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', action ='store', dest='url',  help="URL to query : example.com/graphql?query={}")
    parser.add_argument('-v', action ='store', dest='verbosity', help="Enable verbosity", nargs='?', const=True)
    parser.add_argument('--method', action ='store', dest='method', help="HTTP Method to use interact with /graphql endpoint", nargs='?',  const=True, default="GET")
    results = parser.parse_args() 
    if results.url == None:
        parser.print_help()
        exit()
    return results


def display_help():
    print("[+] \033[92mdump_old    \033[0m: dump GraphQL schema (fragment+FullType)")
    print("[+] \033[92mdump_new    \033[0m: dump GraphQL schema (IntrospectionQuery)")
    print("[+] \033[92mnosqli      \033[0m: exploit a nosql injection inside a GraphQL query")
    print("[+] \033[92mpostgresqli \033[0m: exploit a sql injection inside a GraphQL query")
    print("[+] \033[92mysqli       \033[0m: exploit a sql injection inside a GraphQL query")
    print("[+] \033[92mssqli       \033[0m: exploit a sql injection inside a GraphQL query")
    print("[+] \033[92mexit        \033[0m: gracefully exit the application")
