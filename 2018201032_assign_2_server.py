import socket
import sys
import math
import random
from Crypto.Hash import SHA
import time
import struct

def modulo(a,b,c):
    x=1
    y=a
    while(b>0):
        if(b%2==1):
            x=(x*y)%c
        y=(y*y)%c
        b=b/2
    return x%c

def modulo_inv(a, m) :
    m0=m
    y=0
    x=1
    if(m==1):
        return 0
    while(a>1):
        q=a//m
        t=m
        m=a%m
        a=t
        t=y
        y=x-q*y
        x=t
    if(x<0):
        x=x+m0
    return x

def extendedGcd(a, b):
	x0,x1,y0,y1=1,0,0,1
	while(b!=0):
		q,a,b=a//b,b,a%b
		x0,x1=x1,x0-q*x1
		y0,y1=y1,y0-q*y1    
	return x0

def sigver(PUBKEY,SIGNEDMSG,VERSTATUS):
	m_decimal = int(SIGNEDMSG[0],2)
	print("Value of msg in decimal : "+str(m_decimal))
	#print(m_decimal)
	print("\n")
	c_dash_decimal = int(SIGNEDMSG[1][0],16)%PUBKEY[3]
	print("C decimal : "+str(c_dash_decimal))
	print("S : "+str(SIGNEDMSG[1][1]))
	if SIGNEDMSG[1][1]>=0:
	    s_dash=SIGNEDMSG[1][1]
	else:
		s_dash=(PUBKEY[3]-1)*(-1)*(SIGNEDMSG[1][1])
	#print("S "+str(s_dash))
	temp_1 = modulo_inv(PUBKEY[1],PUBKEY[3])
	temp_2 = modulo(PUBKEY[0],s_dash,PUBKEY[3])
	A_dash = (modulo(temp_1, c_dash_decimal,PUBKEY[3] ) * temp_2 ) % PUBKEY[3]
	temp_3 = modulo_inv(PUBKEY[2],int(PUBKEY[3]))
	temp_4 = modulo(PUBKEY[1],s_dash,int(PUBKEY[3]))
	B_dash = (modulo(temp_3, c_dash_decimal,PUBKEY[3] ) * temp_4 ) % PUBKEY[3]
	print("A dash : "+str(A_dash))
	print("B dash : "+str(B_dash))
	h = SHA.new()
	h.update(str(A_dash)+str(B_dash)+str(SIGNEDMSG[0]))
	c_dash = h.hexdigest()
	print("C dash : "+str(c_dash))
	print("C : "+str(SIGNEDMSG[1][0]))
	if c_dash==str(SIGNEDMSG[1][0]):
		VERSTATUS=1
	else:
		VERSTATUS=0
	return VERSTATUS
    

def send_msg(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

if __name__ == "__main__":
    accept_flag=1
    Portnum = int(input("Enter port number : "))
    msg_flag=1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print("Could not create socket")
        sys.exit()
    print("Socket is created")
    try:
        host = '127.0.0.1'
    except socket.gaierror:
        print("Hostname could not be resolved")
        sys.exit()

    server_address = (host, Portnum)
    print('Starting up on %s port %s' % server_address)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as err:
        print( err)
        sys.exit()
    try:
        sock.bind(server_address)
    except socket.error:
        print( "Binding of socket failed")
        sys.exit()
    print( "Socket is binded")
    sock.listen(1)
    while True:
        print( 'Waiting for connection....')
        try:
            connection, client_address = sock.accept()
        except socket.error:
            print( "Unable to accept the connection")
            sys.exit()
        if msg_flag==1:
            print( 'Connection accepted from'+" "+str(client_address))
            msg_flag=0
        if accept_flag==1:
            accept_flag=0
            try:
                recv_data = recv_msg(connection)
                PUBKEY=[]
                temp = recv_data.split()
                for i in range(0,len(temp)):
                    PUBKEY.append(int(temp[i]))
            except socket.error:
                print( "Unable to receive public elements from A")
                sys.exit()
            print( "\n")
            print( "Received public elements from A\n")
            print( "Public key elements are as follows : ")
            print( PUBKEY)
            print( "\n")
        try:
            recv_data = recv_msg(connection)
            SIGNEDMSG=[]
            temp=recv_data.split()
            SIGNEDMSG.append(str(temp[0]))
            SIGNEDMSG.append((temp[1],int(temp[2])))

        except socket.error:
            print( "Unable to receive signed msg from A")
            sys.exit()
        print( "Received signed msg from A\n")
        print( "Message m in binary : "+str(SIGNEDMSG[0]))
        #print( SIGNEDMSG[0])
        print( "\n")
        print( "Signed msg tuple : ")
        print( SIGNEDMSG[1])
        print( "\n")
        VERSTATUS=0
        VERSTATUS = sigver(PUBKEY,SIGNEDMSG,VERSTATUS)
        print( "Verification status to be sent : ")
        print( VERSTATUS)
        print( "\n")
        try:
            send_data = send_msg(connection,str(VERSTATUS))
        except socket.error:
            print("Unable to send verification status to A")
            sys.exit()
        print("Verification status is send to A")
        print("\n")
        connection.close()

    sock.close()