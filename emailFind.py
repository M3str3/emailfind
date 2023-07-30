from time import sleep
from domains import domains

import json
import smtplib
import dns.resolver
import threading
import argparse
import requests

results = []
no_vision = []

def check_hibp( email:str ) -> None:
    """
    Check if an email address has been compromised using the Have I Been Pwned API.

    Args:
        email (str): The email address to check.
    """
    global results

    print("Waiting for hibp request")
    sleep(3)
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        'hibp-api-key': args.key,  
        'User-Agent': 'Python script'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        print(f"{email} has been exposed in the following services:")
        for d in data:
            print(f"- {d['Name']}")
        if email not in results:
            results.append( email )
    elif response.status_code == 404:
        print(f"{email} has not been found in any compromised service.")
    else:
        print(f"An error occurred while querying Have I Been Pwned: {response.text}")


def check_email( email:str ) -> None:
    """
    Check if an email address is valid and reachable.

    Args:
        email (str): The email address to check.
    Return:
        bool: True if the email is valid and reachable, False otherwise.
    """
    global results, no_vision

    if args.verbose:
        print(f"Trying {email}")

    domain = email.split('@')[1]
    try:
        records = dns.resolver.resolve(domain, 'MX')
    except:
        no_vision.append(email)
        return False

    smtp = smtplib.SMTP()
    smtp.set_debuglevel(0)
    smtp.timeout = 10
    if args.key:
        check_hibp( email )
    try:
        ip = str(records[0].exchange)
        smtp.connect(ip)
        smtp.helo(smtp.local_hostname)

        code, message = smtp.mail(email)
        if code == 250:
            response = smtp.rcpt(email)
            if response[0] == 250:
                results.append(email)
                print(f"Email found!!! {email}")
                return True
            else:
                no_vision.append(email)
                return False
        else:
            no_vision.append(email)
            return False
    except:
        no_vision.append(email)
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user',                         help="Specify a specific email address to check")
    parser.add_argument('-n', '--name',                         help="Provide a name and surname to generate combinations of email addresses")
    parser.add_argument('-r', '--random',                       help="Activate random numbers in the email.")
    parser.add_argument('-t', '--threads', default=3,           help="Number of threads to use.")
    parser.add_argument('-o', '--output',  action='store_true', help="Enable output file.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbosity.")
    parser.add_argument('-k', '--key',                          help="Key for check email breach in hibp")
    parser.add_argument('-d', '--domains',                      help="Select domains to make the check")
    args = parser.parse_args()


    if args.domains:
        domains = args.domains.split(',')

    targets = []
    if args.threads:
        hilos = int(args.threads)
    else:
        hilos = 10

    if args.user:
        targets.append(args.user)
    else:
        if not args.name:
            exit(1)
        print(f"Searching for emails related to {args.name}")
        persona = args.name.lower()
        targets.append(persona.replace(' ', ''))
        targets.append(persona.strip().replace(' ', '.'))
        targets.append(persona.strip().replace(' ', '-'))

        partes = persona.split(' ')
        tmp = partes[0]
        for parte in partes[1:]:
            tmp += parte
        if tmp not in targets:
            targets.append(tmp)

        if args.random:
            for t in range(1, int(args.random)):
                targets.append(f"{t}{persona.strip().replace(' ', '')}")
                targets.append(f"{persona.strip().replace(' ', '')}{t}")

                targets.append(f"{t}{persona.strip().replace(' ', '.')}")
                targets.append(f"{persona.strip().replace(' ', '.')}{t}")

                targets.append(f"{t}{persona.strip().replace(' ', '-')}")
                targets.append(f"{persona.strip().replace(' ', '-')}{t}")

    print(f"Checking with: {targets}")

    for target in targets:
        threads = []
        try:
            for check in domains:
                email = f"{target}@{check}"
                loop = True
                while loop:
                    if threading.active_count() < hilos:
                        t = threading.Thread(target=check_email, args=(email,))
                        t.start()
                        loop = False
                        threads.append(t)
                    else:
                        sleep(1)
        except KeyboardInterrupt:
            exit(1)

        # Wait for the remaining threads to finish
        for thread in threads:
            thread.join()

    print("########################")
    if args.verbose:
        for no_email in no_vision:
            print(f"[X] - {no_email}")
        print('------------')
    if args.output:
        archivo = open(f'{targets[0]}.txt', 'w')
    for email in results:
        print(f"[✓] - {email}")
        if args.output:
            archivo.write(email + "\n")
    print(f"Found: {len(results)}")
