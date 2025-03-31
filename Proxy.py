# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time  # Added for cache age calculation

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
    # Create a server socket
    # ~~~~ INSERT CODE ~~~~
    SocketConnectingServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ##create a TCP socket and listen client connection request
    # ~~~~ END CODE INSERT ~~~~
    print('Created socket')
except:
    print('Failed to create socket')
    sys.exit()

try:
    # Bind the the server socket to a host and port
    # ~~~~ INSERT CODE ~~~~
    SocketConnectingServer.bind((proxyHost, proxyPort))  ##bind the socket to dedicated Ip and port, so it can accept connection
    # ~~~~ END CODE INSERT ~~~~
    print('Port is bound')
except:
    print('Port is already in use')
    sys.exit()

try:
    # Listen on the server socket
    # ~~~~ INSERT CODE ~~~~
    SocketConnectingServer.listen(8) ##listen and bind the interface and socket together
    # ~~~~ END CODE INSERT ~~~~
    print('Listening to socket')
except:
    print('Failed to listen')
    sys.exit()

# continuously accept connections
while True:
    print('Waiting for connection...')
    clientSocket = None

    # Accept connection from client and store in the clientSocket
    try:
        # ~~~~ INSERT CODE ~~~~
        clientSocket, client_address = SocketConnectingServer.accept() #accept client connection and save socket and client address.
        # ~~~~ END CODE INSERT ~~~~
        print('Received a connection')
    except:
        print('Failed to accept connection')
        sys.exit()

    # Get HTTP request from client
    # and store it in the variable: messageBytes
    # ~~~~ INSERT CODE ~~~~
    messageBytes = clientSocket.recv(BUFFER_SIZE)
    # ~~~~ END CODE INSERT ~~~~
    message = messageBytes.decode('utf-8')
    print('Received request:')
    print('< ' + message)

    # Extract the method, URI and version of the HTTP client request 
    requestParts = message.split()
    if len(requestParts) < 3:
        clientSocket.close()
        continue

    method = requestParts[0]
    uri = requestParts[1]
    version = requestParts[2]

    print('Method:\t\t' + method)
    print('URI:\t\t' + uri)
    print('Version:\t' + version)
    print('')

    # Get the requested resource from URI
    # Remove http protocol from the URI
    uri = re.sub('^(/?)http(s?)://', '', uri, count=1)

    # Remove parent directory changes - security
    uri = uri.replace('/..', '')

    # Split hostname from resource name
    resourceParts = uri.split('/', 1)
    hostname = resourceParts[0]
    resource = '/'

    if len(resourceParts) == 2:
        # Resource is absolute URI with hostname and resource
        resource = resource + resourceParts[1]

    print('Requested Resource:\t' + resource)

    # Check if resource is in cache
    try:
        cacheLocation = './' + hostname + resource
        if cacheLocation.endswith('/'):
            cacheLocation = cacheLocation + 'default'

        print('Cache location:\t\t' + cacheLocation)

        fileExists = os.path.isfile(cacheLocation)
        
        # Check whether the file is currently in the cache
        cacheFile = open(cacheLocation, "r")
        cacheData = cacheFile.readlines()

        # Check cache expiration
        cache_content = ''.join(cacheData)
        cache_control_match = re.search(
            r'Cache-Control:\s*max-age=(\d+)', 
            cache_content, 
            re.IGNORECASE
        )
        
        # Get cache max-age setting
        cache_max_age = int(cache_control_match.group(1)) if cache_control_match else 0
        last_modified_time = os.path.getmtime(cacheLocation)
        cache_age_seconds = time.time() - last_modified_time
        
        print(f"Cache file age: {int(cache_age_seconds)} seconds, Max age: {cache_max_age} seconds")
        
        # Validate if cache is expired
        if cache_max_age > 0 and cache_age_seconds > cache_max_age:
            print("Warning: Cache expired, fetching fresh copy")
            raise Exception("Cache expired")

        print('Cache hit! Loading from cache file: ' + cacheLocation)
        # ProxyServer finds a cache hit
        # Send back response to client 
        # ~~~~ INSERT CODE ~~~~
        for line in cacheData:
            clientSocket.send(line.encode()) 
        # ~~~~ END CODE INSERT ~~~~
        
        print('Sent to the client:')
        for line in cacheData: 
            print('> ' + line.strip())

    except Exception as e:
        print(f"Cache miss: {str(e)}")
        originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        print('Connecting to:\t\t' + hostname + '\n')
        try: # Get the IP address for a hostname
            address = socket.gethostbyname(hostname)
            originServerSocket.connect((address, 80))
            print('Connected to origin Server')


            originalServerRequest = f"{method} {resource} {version}"
            originServerRequestHeader = f"Host: {hostname}"
            request = originalServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'
            
            print('Forwarding request to origin server:')
            for line in request.split('\r\n'):
                print('> ' + line)
            
            originServerSocket.sendall(request.encode())
            originServerResponsing = originServerSocket.recv(BUFFER_SIZE)
            clientSocket.sendall(originServerResponsing)
            
            with open(cacheLocation, 'wb') as cache_file:
                cache_file.write(originServerResponsing)
                print('cache file closed')
            
            originServerSocket.close()
            clientSocket.shutdown(socket.SHUT_WR)
            print('client socket shutdown for writing')


        except OSError as err:
            print('origin server request failed. ' + err.strerror)
    
    try:
        clientSocket.close()
    except:
        print('Failed to close client socket')
