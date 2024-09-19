from scapy.all import sniff, IP, TCP, send, Packet
from dotenv import load_dotenv
import pyotp
import os
import sys
import socket
import random
import argparse
import subprocess
import time
import logging
import ipaddress


logging.basicConfig(
	filename	= "hknock.log",
	encoding	= "utf-8",
	filemode	= "a",
	format	= "{asctime} - {levelname} - {message}",
	style		= "{",
	datefmt	= "%Y-%m-%d %H:%M",
	level		= logging.INFO
	)


"""
	hknock.py ver. 1.0a
	
"""

load_dotenv()
# The length of the shared secret must be at least 128 bits.
# https://www.rfc-editor.org/rfc/rfc4226#section-4
API_SECRET				= os.getenv("API_SECRET")
MSG_ENCODING			= 'ascii'
PORTS_SEQUENCE			= [33330, 22220, 44440]
PORT_TO_OPEN			= 50000
IP_TO_KNOCK				= '66.130.220.227'
TIMEOUT_TO_VALIDATE	= 15
# A delay is sometimes necessary for the server to accept connection after sequence has been completed.
POST_SEQ_DELAY			= 5


dynamic_sequence		= PORTS_SEQUENCE.copy()
stop_sniff				= False	# To stop scapy.sniff within stopfilter
start_time_taken		= False
start_seq_timer		= 0.0



def reserved_ports(ports_sequence:list) -> bool:
	"""
	[listening mode]

	Returns true if any port in list is reserved.
	All ports under 1024 are system reserved (RFC 6335).
	They could be used under root privilege.

	:param ports_sequence: List of ports
	"""
	for port in ports_sequence:
		if port < 1024:
			return True
	return False

	

def open_port(port:int) -> bool:
	"""
	[listening mode]

	Opens a port using iptables.

	:param port: a port that will be open.
	"""
	try:
		run_result = subprocess.run(
			["iptables", "-A", "INPUT", "-p", "tcp", 
	 		 "--dport", str(port), "-j", "ACCEPT"], check=True)
		if run_result.returncode != 0:
			logging.error("iptables")
			print(f"Error trying to open port with iptables.")
			return False
		else:
			logging.info("Port %d opened", port)
			return True
	except Exception:
		logging.exception("iptables")
		print(f"Unable to call iptables.")



def listen_for_knocks(packet:Packet) -> None:
	"""
	[listening mode]

	Listens for connections for the ports sequence to be knocked.
	Ports open and time of sequence is checked.

	:param packet: a packet to assess.
	"""
	# Time allowed, in seconds, to receive all ports in sequence, before resetting.
	SEC_BEFORE_SEQUENCE_RESET	= 5
	
	if packet.haslayer(IP) and packet.haslayer(TCP):
		src_ip	= packet[IP].src
		dst_port	= packet[TCP].dport

		# Check if the packet matches the knock sequence.
		if dst_port in dynamic_sequence:
			# Start timer to check how long it took to get the correct ports sequence knocked.
			global start_time_taken, start_seq_timer
			if not start_time_taken:
				start_seq_timer	= time.time()
				start_time_taken	= True

			dynamic_sequence.remove(dst_port)
			if verbose:
				print(f">>> {src_ip}:{dst_port} <<<")
			
			if not dynamic_sequence:
				# The ports sequence was successful at this point.
				# Check how long it took to get the correct knock sequence.
				end_seq_timer			= time.time()
				elapsed_time_ports	= end_seq_timer - start_seq_timer
				print(f"elapsed_time_ports: {elapsed_time_ports}")

				if elapsed_time_ports < SEC_BEFORE_SEQUENCE_RESET:
					global stop_sniff
					stop_sniff = True
					print(f"---- Correct knock sequence received from {src_ip}. ----")
		else:
			print(f"-> {src_ip}:{dst_port}")



def otp_handle_connection(server_socket:socket) -> bool:
	"""
	[listening mode]

	Opens a connection between the client and server to exchange OTP. Returns true if OTP valid.

	:param server_socket: socket on which to send the challenge and receive the resulting OTP.
	:param otp_timeout: socket timeout while establishing connection.
	"""
	server_socket.settimeout(5)

	challenge = random.randint(0, 253402318799)
	try:
		if verbose:
			print(f"Sending challenge to client...")
		server_socket.sendall(str(challenge).encode(MSG_ENCODING))

		# Receive OTP to verify.
		if verbose:
			print(f"Listening on socket to receive data...")
		
		try: 
			data_received	= server_socket.recv(1024)
		except server_socket.timeout:
			if verbose:
				print(f"Timeout waiting for OTP.")
			return False

		if not data_received:
			print(f"Socket closed or no data received.Exiting.")
			exit(1)

		otp_received	= data_received.decode(MSG_ENCODING)
		otp_handler		= pyotp.HOTP(API_SECRET)
		is_otp_valid	= otp_handler.verify(otp_received, challenge)

		if verbose:
			print(f"OTP Valid?: {is_otp_valid} \nOTP received: {otp_received} \nChallenge: {challenge}")

		if is_otp_valid:
			# Open specific port and inform client that OTP is valid
			if open_port(PORT_TO_OPEN):
				if verbose:
					print(f"Port {PORT_TO_OPEN} open.")
			
			server_socket.sendall("Valid".encode(MSG_ENCODING))
			return True
		else:
			return False
	except socket.error as socket_exception:
		print(f"Socket error: {socket_exception}")
	


def port_knock(ip_send:str, ports:list) -> None:
	"""
	[knocking mode]

	Sends a series of TCP SYN packets to the specified IP/ports.

	:param ip_send:	The IP address of the target server.
	:param ports:		The expected list of ports to knock on.
	"""
	for port in ports:
		packet = IP(dst=ip_send) / TCP(dport=port, flags="S")
		# https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html#scapy.sendrecv.send
		send(packet, verbose=True)
		print(f"Knocked port {port}")


def validate_otp(host: str, port: int, timeout: float, verbose:bool) -> None:
	"""
	[knocking mode]

	Connects on server to request challenge, receives challenge, computes OTP, sends back OTP.

	:param host:		Server from which to receive the challenge and send back the OTP.
	:param port:		Port on which to communicate.
	:param timeout:	Socket.timeout.
	:param verbose:	If extra information should be shared with user.
	"""
	MSG_ENCODING = 'ascii'

	try:
		# AF_INET: socket to use the IPv4 address family.
		# SOCK_STREAM: socket to use the TCP protocol (stream-based).
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
			client_socket.settimeout(timeout)

			try:
				if verbose:
					print(f"Trying to connect to {host}:{port}...")
				client_socket.connect((host, port))
				if verbose:
					print(f"Connected to {host}:{port}")
			except socket.error as socket_error:
				logging.exception("socket.error")
				print(f"Unable to connect to {host}:{port} -> {socket_error}")

			while True:
				# Receive data
				data = client_socket.recv(1024)
				if not data:
					print(f"No data received to confirm OTP is valid.")
					break

				message_received	= data.decode(MSG_ENCODING)
	
				if message_received == "Valid":
					if verbose:
						print(f"OTP is valid.")
					break
				else:
					challenge		= int(message_received)
					# Get counter-based OTP from challenge.
					otp_handler		= pyotp.HOTP(API_SECRET)
					otp_from_count =  otp_handler.at(challenge)

					# Send back generated OTP from count provided.
					client_socket.sendall(otp_from_count.encode(MSG_ENCODING))
					if verbose: 
						print(f"Sent: {otp_from_count}\n-----------")
	except socket.timeout:
		logging.exception("socket.timeout")
		print(f"Timeout waiting for host. Exiting.")
		exit(1)



def hotp_exchange(addr:tuple) -> bool:
	"""
	[listening mode]

	Establishes a connection with the client, to exchange challenge (counter) and resulting OTP.
	Returns true when the returned OTP is valid.

	:param addr: a 2-tuple (host, port) representing the client.
	"""
	try:
		if verbose:
			print(f"Opening socket for OTP challenge...")

		if socket.has_dualstack_ipv6():
			server_socket = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
		else:
			server_socket = socket.create_server(addr)

		with server_socket as server:
			server_socket, addr = server.accept()
			with server_socket:
				print(f"Connection from {addr}")
				return otp_handle_connection(server_socket)
	except socket.timeout:
		logging.exception("socket.timeout")
		print(f"Timeout waiting for host.")
		print(f"Exiting.")
		sys.exit(1)



def stopfilter(filler):
	"""
	[listening mode]

	Called to stop scapy.sniff.
	"""
	if stop_sniff == True:
		time.sleep(3)
		return True
	else:
		return False	
	


if __name__ == "__main__":

	parser = argparse.ArgumentParser(
		prog='hknock',
		description='hknock is a port knocker that employs a challenge-response One-Time Password (OTP) system as an additional security measure before opening a port. ',
		epilog='hknock was intended solely for educational purposes. It is not designed to provide robust security and should not be used in a production environment.')
	
	parser.add_argument('-m', '--mode', choices=['listen', 'knock'], default='listen')
	parser.add_argument('-v', '--verbose', action='store_true')

	args		= parser.parse_args()
	verbose	= bool(args.verbose)

	if args.mode == 'knock':
		# ------ Knocking mode ------
		try:
			print(f"Starting *knocking* mode. Press Ctrl+C to interrupt.")
			try:
				ip_address = ''
				ip_address = ipaddress.ip_address(IP_TO_KNOCK)
			except ValueError:
				print(f"The IP address provided is invalid. Exiting.")
				exit(1)
			try:
				# 1. Knock the ports sequence to the 'listener'.
				port_knock(IP_TO_KNOCK, PORTS_SEQUENCE)
				
				# 2. Receive challenge, send back resulting OTP.
				print(f"\n\nValidate OTP in {POST_SEQ_DELAY} sec...\n")
				# Without a pause, the client may not connect, as the server's socket may not be ready.
				time.sleep(POST_SEQ_DELAY)
				validate_otp(IP_TO_KNOCK, PORTS_SEQUENCE[0], TIMEOUT_TO_VALIDATE, verbose)
			except KeyboardInterrupt:
				print(f"\nProgram terminated by user.\n")
		except KeyboardInterrupt:
			print(f"\nProgram terminated by user.\n")
	else:
		# ------ Listening mode ------
		try:
			if not reserved_ports(PORTS_SEQUENCE):
				otp_success	= False

				print(f"Started *listening* mode. Press Ctrl+C to interrupt.")
				while not otp_success:
					sniff(filter="tcp", prn=listen_for_knocks, store=0, stop_filter=stopfilter)

					if hotp_exchange(("", PORTS_SEQUENCE[0])):
						otp_success = True
					else:
						print(f"OTP check failed.")
						if verbose:
							print(f"Ports sequence reset")
						dynamic_sequence	= PORTS_SEQUENCE.copy()
						stop_sniff			= False
						start_time_taken	= False
			else:
				print(f"All ports under 1024 are system reserved. Use different ports")
		except KeyboardInterrupt:
			print(f"\nProgram terminated by user.\n")