#!/usr/bin/python3

from socket import socket as genericsocket, SHUT_RDWR, AF_INET, SOCK_STREAM
from ssl import create_default_context, Purpose, CERT_REQUIRED, OP_NO_TLSv1, OP_NO_TLSv1_1
from subprocess import Popen, PIPE
from ntpath import basename
from time import time as generictime, sleep
from argparse import ArgumentParser



class RunClient:

    # def __init__(self):
    #     pass

    def myintro(self, pshow=False):
        if pshow:
            print('''
#######################################################
Client component for the bCIRT server-client tool
Balazs Lendvay 2020
#######################################################
Requires server and client side certificates!
#######################################################
No input will be transferred to the server!
To gracefully exit, CTRL+C"
#######################################################
            ''')
        else:
            pass

    def prepare_context(self, pserver_cert, pclient_key, pclient_cert):
        context = create_default_context(Purpose.SERVER_AUTH, cafile=pserver_cert)
        context.verify_mode = CERT_REQUIRED
        context.load_cert_chain(certfile=pclient_cert, keyfile=pclient_key)
        context.options |= OP_NO_TLSv1
        context.options |= OP_NO_TLSv1_1
        return context

    def prepare_tls_socket(self):
        return genericsocket(AF_INET, SOCK_STREAM)

    def connect_tls(self, pcontext, pnewsocket, pserver_sni_hostname, phost_addr, phost_port):
        aconn = pcontext.wrap_socket(pnewsocket, server_side=False, server_hostname=pserver_sni_hostname)
        try:
            aconn.connect((phost_addr, phost_port))
            # print("SSL established. Peer: {}".format(conn.getpeercert()))
            print("[i] Connected to: %s:%d" % (phost_addr, phost_port))
        except ConnectionRefusedError:
            print("[x] Connection refused %s:%d!" % (phost_addr, phost_port))
            aconn = None
        return aconn

    # http://code.activestate.com/recipes/213239-recvall-corollary-to-socketsendall/
    def recvall(self, the_socket, timeout='', pbinary=False, psize=4096):
        # setup to use non-blocking sockets
        # if no data arrives it assumes transaction is done
        # recv() returns a string
        the_socket.setblocking(False)
        total_data = []
        data = ''
        begin = generictime()
        if not timeout:
            timeout = 1
        while True:
            # if you got some data, then break after wait sec
            if total_data and generictime() - begin > timeout:
                break
            # if you got no data at all, wait a little longer
            elif generictime() - begin > timeout * 2:
                break
            wait = 0
            try:
                data = the_socket.recv(psize)
                if data:
                    if pbinary:
                        total_data.append(data)
                    else:
                        total_data.append(data.decode())
                    begin = generictime()
                    data = ''
                    wait = 0
                else:
                    sleep(0.1)
            except Exception:
                pass
            # When a recv returns 0 bytes, other side has closed
        result = None
        if pbinary:
            result = b''.join(total_data)
        else:
            result = ''.join(total_data)
        the_socket.setblocking(True)
        return result


    def write_to_file(self, pfilename, poutstr, pappend=True, pbinary=False):
        if pappend:
            fmode = "a+"
        else:
            fmode = "w"
        try:
            if pbinary:
                fmode = fmode + "b"
                with open(pfilename, fmode) as outfile:
                    outfile.write(poutstr)
            else:
                with open(pfilename, fmode) as outfile:
                    outfile.write(poutstr)
        except IOError:
            print("[x] Error writing file")

    def receive_file(self, pconn, pfilename):
        recval_str = self.recvall(the_socket=pconn, pbinary=True)
        self.write_to_file(pfilename=pfilename, poutstr=recval_str, pbinary=True, pappend=False)
        return len(recval_str)



def build_parser():
    parser = ArgumentParser(description='Start bCIRT Agent Client component.', usage='bcirt_agent_client [options]')
    parser.add_argument("--hostname", required=True, action='store', type=str, help="Server listening hostname")
    parser.add_argument("--ip", required=True, action='store', type=str, help="Server listening IP (default: 0.0.0.0")
    parser.add_argument("--port", action='store', type=int, help="Client listening port (default: 8443")
    parser.add_argument("--servercert", action='store', type=str, help="Server certificate file path (default: ./server.pem")
    parser.add_argument("--clientkey", action='store', type=str, help="Client Key file path (default: ./client.key")
    parser.add_argument("--clientcert", action='store', type=str, help="Client certificate file path (default: ./client.pem")
    args = vars(parser.parse_args())
    return args


def main():
    # defaults
    host_addr = '192.168.22.52'
    host_port = 8888
    # server_sni_hostname = '192.168.22.52'
    server_sni_hostname = 'master.fritz.box'
    server_cert = './server2.pem'
    client_cert = './client2.pem'
    client_key = './client2.key'


    args = build_parser()
    if not args['hostname']:
        print("Missing hostname parameter --hostname <hostname fqdn>")
        exit(1)
    else:
        server_sni_hostname = args['hostname']
    if not args['ip']:
        print("Missing IP parameter --ip <IP>")
        exit(1)
    else:
        host_addr = args['ip']
    if args['port']:
        host_port = args['port']
    if args['servercert']:
        server_cert = args['servercert']
    if args['clientkey']:
        client_key = args['clientkey']
    if args['clientcert']:
        client_cert = args['clientcert']

    RunClient().myintro(pshow=True)

    context = RunClient().prepare_context(pserver_cert=server_cert, pclient_key=client_key, pclient_cert=client_cert)
    newsocket = RunClient().prepare_tls_socket()
    myconn = None
    print("[i] Connecting to %s %s:%d" % (server_sni_hostname, host_addr, host_port))
    try:
        myconn = RunClient().connect_tls(
            pcontext=context,
            pnewsocket=newsocket,
            pserver_sni_hostname=server_sni_hostname,
            phost_addr=host_addr,
            phost_port=host_port)
    except OSError:
        print('[x] Error - cannot connect to %s %s:%d' % (server_sni_hostname, host_addr, host_port))
    if myconn:
        try:
            while True:
                data = myconn.recv(1024).decode()
                if data == 'quit!':
                    break
                elif data.startswith("sendfile! "):
                    # if the command is sendfile, proceed to retrieve a file
                    afilepath = data.split(" ", 1)[1]
                    afilename = basename(afilepath)

                    print("[i] Getting file: %s" % (afilepath))
                    print("[i] Writing data to: %s" % (afilename))
                    # confirm data retrieval
                    myconn.send(data.encode())  # send back the error -if any-, such as syntax error
                    # retrieve file
                    writtendata = RunClient().receive_file(pconn=myconn, pfilename=afilename)
                    # data = RunClient().recvall(myconn, pbinary=True, psize=4096)
                    print("[i] Received %d bytes of data from: %s:%d" % (writtendata, host_addr, host_port))
                    # break

                elif data.startswith("getfile! "):
                    # if the command is getfile, proceed to send a file
                    afilepath = data.split(" ", 1)[1]
                    afilename = basename(afilepath)
                    print("[i] Getting file: %s" % (afilepath))
                    # print("Getting file: %s" % (afilename))
                    with open(afilepath, mode='rb') as myfile:  # b is important -> binary
                        try:
                            fileContent = myfile.read()
                        except OSError:
                            print("[x] File read error!")
                    myconn.send(fileContent)  # send back the error -if any-, such as syntax error
                    print("[i] Sent %d bytes file %s to: %s:%d" % (len(fileContent), afilepath, host_addr, host_port))
                    # break
                else:
                    CMD = Popen(data,
                                shell=True,
                                universal_newlines=True,
                                stdout=PIPE,
                                stderr=PIPE,
                                stdin=PIPE)
                    CMD_stdout = CMD.stdout.read().encode()
                    CMD_stderr = CMD.stderr.read().encode()
                    CMD_output = b"ERROR: "
                    if CMD_stdout and CMD_stdout != b'':
                        CMD_output = CMD_stdout
                        # print(CMD_stdout.decode())
                    if CMD_stderr and CMD_stderr != b'':
                        CMD_output = CMD_output + CMD_stderr
                        # print(CMD_stderr.decode())
                    if not CMD_output:
                        CMD_output = b"ERROR"
                    myconn.send(CMD_output)  # send back the error -if any-, such as syntax error
                    print("%s:%d: %s" % (host_addr, host_port, data))
                    print("%s" % CMD_output.decode())
        except KeyboardInterrupt:
            print("[i] Keyboard Interrupt - disconnecting")
            myconn.send(b'quit!')
            myconn.shutdown(SHUT_RDWR)
            myconn.close()
        except OSError:
            print("[x] OS error - disconnected")
            myconn.close()
        except EOFError:
            print("[x] EOF - disconnected")
            myconn.close()
        finally:
            print("[i] Closing connection")
            # conn.shutdown(socket.SHUT_RDWR)
            myconn.close()
    else:
        print("[x] No connection")

main()

print("[i] Program exits...bye!")
