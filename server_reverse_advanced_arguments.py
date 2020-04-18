#!/usr/bin/python3

from socket import socket as genericsocket, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from ssl import create_default_context, Purpose, CERT_REQUIRED, OP_NO_TLSv1, OP_NO_TLSv1_1
from time import time as generictime, sleep
from ntpath import basename
from argparse import ArgumentParser

# listen_addr = '192.168.22.52'
# listen_port = 8888
# server_cert = '/home/bali/PycharmProjects/Server_Client/server.pem'
# server_key = '/home/bali/PycharmProjects/Server_Client/server.key'
# client_certs = '/home/bali/PycharmProjects/Server_Client/client.pem'

#server_cert = '/home/bali/PycharmProjects/Server_Client/server2.pem'
#server_key = '/home/bali/PycharmProjects/Server_Client/server2.key'
#client_certs = '/home/bali/PycharmProjects/Server_Client/client2.pem'


class RunServer:

    def __init__(self):
        self.pout = None  # this specifies the output method
        self.poutfile = None  # this is the output file
        self.pappend = False  # append to outfiles or overwrite?

    def myintro(self, pshow=False):
        if pshow:
            print('''
#######################################################
Server component for the bCIRT server-client tool
Balazs Lendvay 2020
#######################################################
Requires server and client side certificates!
#######################################################
Settings:        "set!"
Get file:        "getfile! <FILEPATH>"
Send file:       "sendfile! <FILEPATH>"
Receive buffer:  press enter without input!
Connection help: "?!"
Exit gracefully: "quit!"
#######################################################
            ''')
        else:
            pass

    def prepare_context(self, pserver_cert, pserver_key, pclient_certs):
        context = create_default_context(Purpose.CLIENT_AUTH)

        context.verify_mode = CERT_REQUIRED
        context.load_cert_chain(certfile=pserver_cert, keyfile=pserver_key)
        context.load_verify_locations(cafile=pclient_certs)
        context.options |= OP_NO_TLSv1
        context.options |= OP_NO_TLSv1_1
        # context.options |= socket.SOL_SOCKET
        # context.options |= socket.SO_REUSEADDR
        return context

    def prepare_tls_socket(self, plisten_addr, plisten_port):

        bindsocket = genericsocket()
        # line below allows to reuse the port even if the tool was frozen or didn't close it
        bindsocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        bindsocket.bind((plisten_addr, plisten_port))
        bindsocket.listen(5)

        return bindsocket

    def socket_accept(self, pbindsocket):
        return pbindsocket.accept()

    def socket_close(self, pbindsocket):
        return pbindsocket.close()

    # http://code.activestate.com/recipes/213239-recvall-corollary-to-socketsendall/
    def recvall(self, the_socket, timeout='', pbinary=False):
        # setup to use non-blocking sockets
        # if no data arrives it assumes transaction is done
        # recv() returns a string
        the_socket.setblocking(0)
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
                data = the_socket.recv(4096)
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
        return result

    def connect_tls(self, pcontext, pnewsocket):
        return pcontext.wrap_socket(pnewsocket, server_side=True)

    def check_command(self, pcommand):
        outfilename = None
        if pcommand == "set!":
            print('''
#### Settings ####
Options:
  "outfile" - write output to file - ONLY UTF-8 characters in output!!!
  "append"  - append outputs to outfile
            ''')
            commandin = input("Type a command: ")
            if commandin == "outfile":
                outfilename = input("Filename (leave empty to cancel: ")
                if outfilename == '':
                    self.poutfile = None
                    print("[i] Output set to: display")
                else:
                    self.poutfile = outfilename
                    print("[i] Output set to: %s" % (self.poutfile))
            elif commandin == "append":
                appendselection = input("Y or N (Y is default): ")
                if appendselection == "Y":
                    self.pappend = True
                    print("[i] Output is appended to files")
                elif appendselection == "N":
                    self.pappend = False
                    print("[i] Output overwrites files without asking!!!")
            pcommand = ''
        elif pcommand == "?!":
            self.myintro(pshow=True)
            pcommand = ''
        return (pcommand, outfilename)

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

    def process_result(self, poutstr, poutfile=None, pbinary=False, pappend=True):
        if poutfile is None:
            return poutstr
        else:
            self.write_to_file(pfilename=poutfile, poutstr=poutstr, pbinary=pbinary, pappend=pappend)
            return "Received %d bytes file %s " % (len(poutstr), poutfile)

    def run_command(self, pbindsocket, pconn, proot=""):
        try:
            while True:
                commandinput = input("%s$ " % proot)  # Get user input and store it in command variable
                # If we got terminate command, inform the client and close the connect and break the loop
                # print(command)
                command, outfilename = self.check_command(pcommand=commandinput)
                if command == 'quit!':
                    pconn.send(b'quit!')
                    pconn.close()
                    break
                elif command.startswith('sendfile! '):
                    # if sending a file, send as binary
                    sfilepath = command.split(" ", 1)[1]
                    print("[i] Sending file: %s" % (sfilepath))
                    sfilename = basename(sfilepath)
                    # send intitial command
                    pconn.send(command.encode())
                    # retrieve the initial command to confirm action
                    recval_str = self.recvall(the_socket=pconn, pbinary=False)
                    recval = self.process_result(poutstr=recval_str, poutfile=None, pbinary=False, pappend=self.pappend)

                    #check if sent and received is the same:
                    if command == recval:
                        #send the file
                        print("[i] Reading file contents...")
                        with open(sfilepath, mode='rb') as myfile:  # b is important -> binary
                            try:
                                fileContent = myfile.read()
                            except OSError:
                                print("[x] File read error!")
                        # senddata = b'x' + 1111 * b'test' + b'x'
                        # pconn.send(senddata)
                        # print("Sending %d data..." % len(senddata))
                        pconn.send(fileContent)  # send back the error -if any-, such as syntax error
                        print("[i] Sending %d bytes data..." % len(fileContent))
                        sleep(4)
                        print("[i] Data sent.")
                    else:
                        # pconn.send(b'')
                        print("[!] sent and received filename don't match!!")
                        pass
                elif command.startswith('getfile! '):
                    # if receiving a file, save to the output folder receive as binary
                    afilepath = command.split(" ", 1)[1]
                    print("[i] Getting file: %s" % (afilepath))
                    afilename = basename(afilepath)
                    pconn.send(command.encode())
                    recval_str = self.recvall(the_socket=pconn, pbinary=True)
                    print(self.process_result(poutstr=recval_str, poutfile=afilename, pbinary=True, pappend=self.pappend))
                    # if recval_str == 'quit!':
                    #     print("[i] Client disconnected")
                    #     pconn.close()
                    #     break
                    ## remove below once ready!!!
                    # pconn.send(b'quit!')
                    # pconn.close()
                    ## remove end
                    # break
                elif command != '':
                    # checks of a generic command is specified
                    pconn.send(command.encode())  # Otherwise we will send the command to the target
                    # print(conn.recv(1024).decode())  # and print the result that we got back
                    recval_str = self.recvall(the_socket=pconn)
                    print(self.process_result(poutstr=recval_str, poutfile=self.poutfile))
                    # print(recval_str)
                    # print("NEED TO FILE THIS")
                    if recval_str == 'quit!':
                        print("[i] Client disconnected")
                        pconn.close()
                        break
                else:
                    # This checks if the connection is still alive and if anything is in the pipe
                    recval_str = self.recvall(the_socket=pconn)
                    if recval_str == 'quit!':
                        print("[i] Client disconnected")
                        pconn.close()
                        break
                    elif recval_str:
                        print(recval_str)
                    else:
                        print("[i] No data in the pipe, check again later!")
        except KeyboardInterrupt:
            print("[i] Disconnecting")
            pconn.send(b'quit!')
            try:
                pconn.shutdown(SHUT_RDWR)
            except OSError:
                pass
            pconn.close()
            self.socket_close(pbindsocket=pbindsocket)
            print("[i] Disconnected with Keyboard Interrupt")
            # break
        except OSError:
            print("[i] Disconnecting")
            pconn.send(b'quit!')
            try:
                pconn.shutdown(SHUT_RDWR)
            except OSError:
                pass
            pconn.close()
            self.socket_close(pbindsocket=pbindsocket)
            print("[i] Disconnected with OS Error")
            # break
        except EOFError:
            print("[i] Disconnecting")
            pconn.send(b'quit!')
            try:
                pconn.shutdown(SHUT_RDWR)
            except OSError:
                pass
            pconn.close()
            self.socket_close(pbindsocket=pbindsocket)
            print("[i] Disconnected with EOFError")
            # break
        except BrokenPipeError:
            print("[i] Disconnecting")
            pconn.send(b'quit!')
            try:
                pconn.shutdown(SHUT_RDWR)
            except OSError:
                pass
            pconn.close()
            self.socket_close(pbindsocket=pbindsocket)
            print("[i] Disconnected with Broken Pipe")
            # break
        finally:
            print("[i] Closing connections")
            try:
                pconn.shutdown(SHUT_RDWR)
            except OSError:
                pass
            pconn.close()
            print("[i] Disconnected gracefully")

            # conn.close()
        return True


def build_parser():
    parser = ArgumentParser(description='Start bCIRT Agent Server component.', usage='bcirt_agent_server [options]')
    parser.add_argument("--ip", required=True, action='store', type=str, help="Server listening IP (default: 0.0.0.0")
    parser.add_argument("--port", action='store', type=int, help="Server listening port (default: 8443")
    parser.add_argument("--serverkey", action='store', type=str, help="Server Key file path (default: ./server.key")
    parser.add_argument("--servercert", action='store', type=str, help="Server certificate file path (default: ./server.pem")
    parser.add_argument("--clientcert", action='store', type=str, help="Client certificate file path (default: ./client.pem")
    args = vars(parser.parse_args())
    return args


def main():
    # defaults
    listen_addr = '0.0.0.0'
    listen_port = 28123
    server_cert = './server2.pem'
    server_key = './server2.key'
    client_certs = './client2.pem'

    args = build_parser()
    if not args['ip']:
        print("Missing IP parameter --ip <IP>")
        exit(1)
    else:
        listen_addr = args['ip']
    if args['port']:
        listen_port = args['port']
    if args['serverkey']:
        server_key = args['serverkey']
    if args['servercert']:
        server_cert = args['servercert']
    if args['clientcert']:
        client_certs = args['clientcert']


    RunServer().myintro(pshow=True)

    context = RunServer().prepare_context(pserver_cert=server_cert, pserver_key=server_key, pclient_certs=client_certs)
    bindsocket = RunServer().prepare_tls_socket(plisten_addr=listen_addr, plisten_port=listen_port)

    while True:
        print("[i] Waiting for client on %s:%d" % (listen_addr, listen_port))
        newsocket = None
        fromaddr = None
        try:
            newsocket, fromaddr = RunServer().socket_accept(pbindsocket=bindsocket)
            print("[i] Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
            # newsocket, fromaddr = bindsocket.accept()
        except KeyboardInterrupt:
            print("[i] Keyboard Interrupt - disconnecting")
            RunServer().socket_close(pbindsocket=bindsocket)
            break
        except OSError:
            print("[x] OS error - disconnected")
            RunServer().socket_close(pbindsocket=bindsocket)
            break
        except EOFError:
            print("[x] EOF - disconnected")
            RunServer().socket_close(pbindsocket=bindsocket)
            exit(2)
        try:
            myconn = RunServer().connect_tls(pcontext=context, pnewsocket=newsocket)
            mycert = myconn.getpeercert()
            RunServer().run_command(pbindsocket=bindsocket, pconn=myconn, proot=fromaddr[0])
        except Exception:
            print("[x] Certificate or TLS version issue!")

        # print(repr(conn.getpeername()))
        # print(conn.cipher())
        # print("SSL established. Peer: {}".format(cert))

        # buf = b''  # Buffer to hold received client data
    # no bindsocket.close()
    RunServer().socket_close(pbindsocket=bindsocket)

main()

print("[i] Program exits...bye!")
