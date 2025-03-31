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
        cacheLocate = './' + hostname + resource
        if cacheLocate.endswith('/'):
            cacheLocate = cacheLocate + 'default'

        print('Cache location:\t\t' + cacheLocate)

        file_exists = os.path.isfile(cacheLocate)
        
        # Check whether the file is currently in the cache
        with open(cacheLocate, "r") as cache_file:
            cacheData = cache_file.readlines()
            cache_string = ''.join(cacheData)

            ##check if it's expired
            matchingCacheCtrol = re.search(r'CacheCtrl:.*?maxAge = (\d+)', cache_string, re.IGNORECASE)
            maxAge = int(matchingCacheCtrol.group(1)) if matchingCacheCtrol else None
            timeModi = os.path.getmtime(cacheLocate)
            age = time.time() - timeModi
            print(f"The age of caching file is {int(age)} secs")
            
            if maxAge is not None and age >= maxAge:
                print("cache has been expired.")
                raise Exception("Cache has been expired!")

            print('Cache hit! Loading from cache file: ' + cacheLocate)
            # ProxyServer finds a cache hit
            # Send back response to client 
            # ~~~~ INSERT CODE ~~~~
            for line in cacheData:
                clientSocket.send(line.encode()) 
                ##Sends cached content back to the client to avoid repeated requests and improve access speeds
            # ~~~~ END CODE INSERT ~~~~
            
            print('Sent to the client:')
            ##check the cache data print and fix
            for line in cacheData: 
                print('> ' + line.strip())

    except Exception as e:
        print(f"Cache miss: {str(e)}")
        # cache miss. Get resource from origin server
        originSocketConnectingServer = None
        # Create a socket to connect to origin server
        # and store in originServerSocket
        # ~~~~ INSERT CODE ~~~~
        originSocketConnectingServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ##pull resourse from cache, if don't have, require from original server
        # ~~~~ END CODE INSERT ~~~~

        print('Connecting to:\t\t' + hostname + '\n')
        try:
            # Get the IP address for a hostname
            address = socket.gethostbyname(hostname)
            # Connect to the origin server
            # ~~~~ INSERT CODE ~~~~
            originSocketConnectingServer.connect((address, 80))
            # ~~~~ END CODE INSERT ~~~~
            print('Connected to origin Server')

            originalServerRequest = ''
            originalServerRequestHeader = ''
            # Create origin server request line and headers to send
            # and store in originServerRequestHeader and originServerRequest
            # originServerRequest is the first line in the request and
            # originServerRequestHeader is the second line in the request
            # ~~~~ INSERT CODE ~~~~
            originalServerRequest = f"{method} {resource} {version}"
            originalServerRequestHeader = f"Host: {hostname}"
            # ~~~~ END CODE INSERT ~~~~

            # Construct the request to send to the origin server
            request = originalServerRequest + '\r\n' + originalServerRequestHeader + '\r\n\r\n'

            # Request the web resource from origin server
            print('Forwarding request to origin server:')
            for line in request.split('\r\n'):
                print('> ' + line)

            try:
                originSocketConnectingServer.sendall(request.encode())
            except socket.error:
                print('Forward request to origin failed')
                sys.exit()

            print('Request sent to origin server\n')

            # Get the response from the origin server
            # ~~~~ INSERT CODE ~~~~
            originServerResponsing = originSocketConnectingServer.recv(BUFFER_SIZE)
            # ~~~~ END CODE INSERT ~~~~

            # Send the response to the client
            # ~~~~ INSERT CODE ~~~~
            clientSocket.sendall(originServerResponsing)
            # ~~~~ END CODE INSERT ~~~~

            ##check if can be cached
            string_response = originServerResponsing.decode('ISO-8859-1')

            no_store = re.search(r'Not store this cache control:', string_response, re.IGNORECASE)

            ##judge if can be cached
            go_cache = True
            if no_store:
                go_cache = False

            #It should be cache down below
            if go_cache:
                # Create a new file in the cache for the requested file.
                cache_dir, file = os.path.split(cacheLocate)
                print('cached directory ' + cache_dir)
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir)
                
                with open(cacheLocate, 'wb') as cache_file:
                    # Save origin server response in the cache file
                    # ~~~~ INSERT CODE ~~~~
                    cache_file.write(originServerResponsing)
                    # ~~~~ END CODE INSERT ~~~~
                    print('cache file closed')

            # finished communicating with origin server - shutdown socket writes
            print('origin response received. Closing sockets')
            originSocketConnectingServer.close()
            
            clientSocket.shutdown(socket.SHUT_WR)
            print('client socket shutdown for writing')
        except OSError as err:
            print('origin server request failed. ' + err.strerror)

    try:
        clientSocket.close()
    except:
        print('Failed to close client socket')