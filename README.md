# hknock.py

hknock.py is a port knocker that employs a challenge-response One-Time Password (OTP) system as an additional security measure before opening a port.

The server, referred to as the 'listener', monitors for the correct port knocking sequence. The client, known as the 'knocker', is required to complete the sequence in the correct order within a specified timeframe. Upon receiving the correct sequence, the 'listener' sends a random iteration number (a challenge) to the 'knocker', representing a specific count for a counter-based OTP.

The 'knocker' then calculates the OTP for that particular iteration using a shared secret key and sends the response back to the 'listener'. The 'listener' verifies the response against its own calculation to authenticate the 'knocker'. If the response is correct, a predefined port is opened.

Note: This program is a proof of concept and is not intended to replace encrypted communication channels (e.g., SSH). It serves as an additional layer of security through obfuscation, aiming to reduce the attack surface and potentially safeguard existing channels against zero-day exploits. For more robust port knocking solutions, consider using established systems such as fwknop or COKd.

**Important Notice:**

This port knocker is intended solely for educational purposes. It is not designed to provide robust security and should not be used in a production environment. The implementation has limitations and vulnerabilities that make it unsuitable for real-world security applications. The primary purpose of this project was to explore programming concepts and discover the Python language.
	
**Some limitations:**

No Throttling Parameter: The 'listener' will continue running until manually stopped. When the correct port sequence is knocked, the 'listener' will wait for an OTP. If no response is received or if the response is incorrect, the server will reset the port sequence and continue listening.

Pseudo-Random Challenge Generation: The challenge number is generated using a pseudo-random generator, which is not suitable for security purposes. For cryptographic uses, consider using the secrets module as outlined in PEP-0506 (https://peps.python.org/pep-0506/).

No Whitelisting or Blacklisting: The implementation does not include whitelisting or blacklisting features.

Reduced OTP Entropy: The HOTP algorithm was designed for users to manually enter the hash result, leading to truncation of the HMAC-SHA-1 output from 160 bits to a more manageable length. However, with hknock, truncation is unnecessary. Using the full 160-bit output would provide greater entropy, enhancing resistance to brute-force attacks and reducing predictability.

Weak Hash Function: SHA-1 is considered weak due to known vulnerabilities. For new applications, it is recommended to use stronger hash functions such as SHA-256 or SHA-3.

Ideally, this should run as a daemon.

Several factors can prevent a port from being successfully knocked:
 - Network issues (latency, squirrels)
 - Firewalls (rate limiting, blocked IP or port)
 - Wrong configurations
 - IDS, IPS, etc.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

Tested with python 3.9 and 3.12 on Linux Mint 20.3
hknock.py requires the following additional libraries:
- scapy 	[https://scapy.readthedocs.io/en/latest/installation.html]
- dotenv	[https://pypi.org/project/python-dotenv/]
- pyotp	[https://pyauth.github.io/pyotp/]

**command-line utility**
- iptables is required.

**.env file**
- Create an .env file and save your secret key (example below). You will need a base32 key (RFC 4648).

	API_KEY=base32
	API_SECRET=JBSWY3DPFVQQ2ZLNNV4TK4LHFA

## Usage

usage: hknock [-h] [-m {listen,knock}] [-v]

options:
  -h, --help           show this help message and exit
  -m {listen,knock}, --mode {listen,knock}
  -v, --verbose

*** Listen mode ***
First, always start hknock in _listen mode_ on the server. Here's an example:
	python3 hknock.py -m listen

*** knock mode ***
After, start hknock in _knock mode_ on the client. Here's an example, with verbose enabled:
	python3 hknock.py -v -m knock

## License

The MIT License - details in LICENSE file.