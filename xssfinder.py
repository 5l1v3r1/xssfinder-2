import concurrent.futures # For multithreading
import colorama # For colors in terminal
import requests # For fecthing data
import argparse # Taking input
import sys # To interact with system
import urllib.parse as urlparse # Getting parameters from URLs

#Colors Code
RED   = '\033[91m'
GREEN = '\033[92m'
YELLOW= '\033[93m'
DBLUE = '\033[94m'
BLUE  = '\033[96m'
WHITE = '\033[0m'

# Function to print the Banner
def banner():
    print(f'''
{GREEN}
____  __                  ______________       _________
__  |/ /______________    ___  ____/__(_)____________  /____________
__    /__  ___/_  ___/    __  /_   __  /__  __ \  __  /_  _ \_  ___/
_    | _(__  )_(__  )     _  __/   _  / _  / / / /_/ / /  __/  /
/_/|_| /____/ /____/      /_/      /_/  /_/ /_/\__,_/  \___//_/


Tool to find Xss Vulnerbilities in your website
{BLUE}
TEAM XSS'd
• Joel verghese • Ayushi Rawat • Nincy Samuel • Gitesh Sharma
{WHITE}
''')

# Function to print errors for wrong input
def parser_error(errmsg):
    banner()
    print("Use \"xssfinder -h\" for help")
    print()
    print(RED + "Error: " + errmsg + WHITE)
    sys.exit()

# Func to made get request
def getreq(u):
    url=u[0] # Getting url
    site = requests.get(url) # Requesting URL using GET method
    data = site.text # Getting source code pf requested url
    return data

# Multithreading for get request
def bulletget(urls):

    # Using concurrent.futures for multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:

        # R will get all the results in it
        R = {executor.submit(getreq, u): u for u in urls}

        # As soon as thread will complete, this will fetch the result of that thread
        for r in concurrent.futures.as_completed(R):
            u = R[r] # Getting the value whose result has been completed
            url = u[0] # Getting Url from that value
            payload = u[1] # Getting payload of that value
            try:
                # Getting the source code from request
                data = r.result()
            except Exception as e:
                # Print error if any exists
                print(f'{RED} [Error] {url} {e}')
            else:
                # Checking for relfected value in source code
                if payload.split('=')[1] in data:
                    print(f'{RED} [Vulnerable] {payload}')
                else :
                    print(f'{GREEN} [Not Vulnerable] {payload}')

# Func to made post request
def postreq(u):
    url=u[0] # Getting url
    payload=u[1] # Getting payload
    data = {param:payload} # Setting post req parameters
    site = requests.post(url, data = data) # Requesting URL using POST method
    data = site.text # Getting source code pf requested url
    return data

# Multithreading for post request
def bulletpost(urls):

    # Using concurrent.futures for multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:

        # R will get all the results in it
        R = {executor.submit(postreq, u): u for u in urls}

        # As soon as thread will complete, this will fetch the result of that thread
        for r in concurrent.futures.as_completed(R):
            u = R[r] # Getting the value whose result has been completed
            payload = u[1] # Getting payload from that value
            try:
                # Getting the source code from request
                data = r.result()
            except Exception as e:
                # Print error if any exists
                print(f'{RED} [Error] {url} {e}')
            else:
                # Checking for relfected value in source code
                if payload in data:
                    print(f'{RED} [Vulnerable] {payload}')
                else :
                    print(f'{GREEN} [Not Vulnerable] {payload}')

# Using argparse library for taking input
def parse_args():
    parser = argparse.ArgumentParser(epilog=f"\t{BLUE}Example:{WHITE} xssfinder -u https://www.google.com/index.php?new=something")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-u', '--url', help="Url to test", required=True)
    parser.add_argument('-r', '--request', help="Set request to GET/POST", required=True)
    parser.add_argument('-p','--param', help="parameter to test", required=True)
    parser.add_argument('-t', '--threads', help='No of threads(request) per seconds', type=int, default=30)
    return parser.parse_args()

# main function of the program
def main(url, req, param, threads):

    #Printing general information
    print(f'''Url        | {url}
Request    | {req}
Parameter  | {param}
Threads    | {threads}''')

    # Listof payloads
    payloads = ['"><script>alert(1)</script>','"><img src=x onerror="alert(1)">','" onclick="alert(1)"']

    # Checking request if GET or POST
    if req.lower() == 'get':
        # Getting parsed url, which contain host, method, querys etc
        parsed = urlparse.urlparse(url)
        # Taking parameters from parsed list
        allParams = parsed.query.split("&")

        #Finding parameter supplied by user to test
        for p in allParams:
            if (param+'=') in p:
                param=p
                break

        urlList=[] # list of URLS to test (Adding payload in URL)

        for payload in payloads:
            payload=param.split('=')[0]+'='+payload
            urlList.append([url.replace(param,payload),payload])

        # Calling multithreading func with list of urls
        bulletget(urlList)

    elif req.lower() == 'post':
        print(f'\n{BLUE}[POST] Preparing...')

        urlList=[] # list of URL + Payload
        for payload in payloads:
            urlList.append([url,payload])

        # Calling multithreading func with list of urls
        bulletpost(urlList)

    else:
        print(f'{RED} Request method can have get or post value')

# ------------------------------------------------------------
# Welcome to XSS Finder
# This tool can find XSS vulnerabilities in your site
# Team
# Joel verghese • Ayushi Rawat • Nincy Samuel • Gitesh Sharma
# -----------------------------------------------------------

# Beginning of program

# Calling function to take input
args = parse_args()

# Setting input into global variables
url = args.url           # setting url to test
req = args.request       # setting GET/POST req
param = args.param       # parameter to test
threads = args.threads   # no of threads

# Calling banner function to print banner
banner()

# Starting the main process by calling main func
main(url, req, param, threads)
