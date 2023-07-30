# EmailFind

## Description
This repository contains a Python script called "emailfind.py" that allows you to check the validity and reachability of email addresses. The script utilizes standard Python libraries and the "Have I Been Pwned" API for performing the email checks.

## Prerequisites

Before running the script, make sure you have the following Python libraries installed:
    dns.resolver

You can install them using `pip`:

````bash
pip install dnspython==2.0.0
````

## How to Use the Script

The script can be executed from the command line with several options to customize the email verification process. Below are the available options:

````bash
python emailfind.py -u USER -n "NAME AND SURNAME" -r NUM_RANDOM -t NUM_THREADS -o -v -k API_KEY -d DOMAIN1,DOMAIN2,...
````
- **-u**, **--user**: Specify a specific email address to check.
- **-n**, **--name**: Provide a name and surname to generate combinations of email addresses.
- **-r**, **--random**: Activate the generation of random numbers in the email address.
- **-t**, **--threads**: Set the number of threads to use for verification.
- **-o**, **--output**: Enable the creation of an output file to save the found valid email addresses.
- **-v**, **--verbose**: Enable detailed progress messages during script execution.
- **-k**, **--key**: Provide the API key to use the "Have I Been Pwned" API.
- **-d**, **--domains**: Select specific domains to perform the verification. Provide them separated by commas.

## How modify domains to check

Use domains.py to define the amount of domains you wanna check

## How the Script Works

The "emailfind.py" script performs the following actions:

1. Checks the existence of an email address in the "Have I Been Pwned" API to detect if it has been compromised in any data breaches.

2. Validates and verifies the accessibility of an email address using DNS and SMTP protocols.

3. It can perform email checks on specific emails or generate combinations based on a name and surname, as well as generate variants with random numbers.

4. The verification is done concurrently using multiple threads to improve efficiency.

5. The verification results are displayed in the standard output, showing the found valid email addresses and those that have not been validated.

6. If the output file option is enabled, the valid email addresses are saved in a file named "USER.txt" (replacing "USER" with the value of the -u argument).

## Additional Notes

The script uses a module file called "domains.py" that contains a variable domains with a list of valid domains for verification. Make sure to provide this file or modify the script to include the list of domains you want to check.

A valid "Have I Been Pwned" API key is required to use the email breach verification in the API. If a valid API key is not provided, this functionality will not be enabled.

Example Usage
````bash
python emailfind.py -u user -t 5 -o -v -k YOUR_API_KEY -d example.com,example.org
````
