#!/usr/bin/env python3

# This is a simple demo application for the server in our attack. It accepts
# multiple connections on TCP Port 2440 (or the command-line arguments), echoing
# back whatever it receives on each accepted connection.

import argparse
import asyncio
import socket

class EchoSocket(asyncio.Protocol):
    """A socket that echoes back whatever it receives, for use with `asyncio`

    Note that an instance of this class is created for every connection to the
    server. This means we don't have to do multiplexing ourselves - `asyncio`
    takes care of that for us.

    Other than that, this class just implements the API required to pass to
    `create_server` in `asyncio`.
    """

    def connection_made(self, transport):
        # The documentation says we're responsible for storing the transport
        self.transport = transport
        self.peername = transport.get_extra_info('peername')
        print(f"[*] Made connection to {self.peername}")

    def data_received(self, data):
        # Just echo back. This simple implementation doesn't handle flow
        # control, so we risk overrunning the buffer. For our purposes, this is
        # fine.
        self.transport.write(data)
        print(f"    Received {len(data)} bytes from {self.peername}")

    def connection_lost(self, exc):
        # The argument is an exception on abnormal failure, or None on EOF
        if exc is None:
            print(f"[-] Received EOF from {self.peername}")
        else:
            print(f"[x] Lost connection to {self.peername}: {exc}")

async def main(args: argparse.Namespace):
    # Get the loop and create the server on it
    loop = asyncio.get_event_loop()
    server = await loop.create_server(EchoSocket, host='0.0.0.0', family=socket.AF_INET, port=args.port)
    print(f"[*] Listening on {args.port}")
    await server.serve_forever()

if __name__ == '__main__':

    # Parse command-line arguments
    parser = argparse.ArgumentParser(prog="echo.py", description="Server for the attack")
    parser.add_argument("-p", "--port", metavar='PORT', type=int, default=2440, help="Port to listen on")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Got keyboard interrupt, exiting...")
        pass
