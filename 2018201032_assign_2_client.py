
import socket
import sys
import math
import random
import numpy as np
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

def millerrabin(n,ite):
    if(n<2):
        return False
    if(n!=2 and n%2==0):
        return False
    d=n-1
    while(d%2==0):
        d=d/2
    for i in range(ite):
       a = random.randint(1,n-1)
       temp = d
    x = modulo(a,temp,n)
    while(temp!=n-1 and x!=1 and x!=n-1):
        x = (x*x)%n
        temp = temp*2
    if(x!=n-1 and temp%2==0):
        return False
    return True

def primeFactors(n,min_prime):
    temp=[]
    while n % 2 == 0:
        if 2 not in temp:
            if 2>=min_prime:
                temp.append(2)
        n = n / 2
    for i in range(3,int(math.sqrt(n))+1,2):
        while n % i== 0:
            if i not in temp:
                if i>=min_prime:
                    temp.append(i)
            n = n / i
    if n > 2:
        if n not in temp:
            if n>=min_prime:
                temp.append(n)
    if len(temp)>=1:
        return temp
    else:
        temp=[]
        return temp


def keygen(PUBKEY):
	max_prime=1000000
	it=4
	min_prime=10001
	while 1:
		q = np.random.randint(min_prime,max_prime)
		if millerrabin(q,it)==True:
			break
	g=3
	a = np.random.randint(1,q-1)
	y1=modulo(g,a,q)
	y2=modulo(y1,a,q)
	PUBKEY.append(int(g))
	PUBKEY.append(int(y1))
	PUBKEY.append(int(y2))
	PUBKEY.append(int(q))
	return PUBKEY,int(a),q

def siggen(PUBKEY,a,m,SIGNEDMSG,q):
	m_decimal = int(m,2)
	print( "Value of msg in decimal : ")
	print( m_decimal)
	r=np.random.randint(1,q-1)
	A=modulo(PUBKEY[0],r,q)
	B=modulo(PUBKEY[1],r,q)
	print("A : "+str(A))
	print("B : "+str(B))
	h = SHA.new()
	h.update(str(A)+str(B)+str(m))
	c = h.hexdigest()
	c_decimal = int(h.hexdigest(),16)%PUBKEY[3]
	print("C decimal : "+str(c_decimal))
	s = ( ( ((a%(PUBKEY[3]-1)) * (c_decimal%(PUBKEY[3]-1))%(PUBKEY[3]-1) ) + r%(PUBKEY[3]-1) )%(PUBKEY[3]-1))
	print("S : "+str(s))
	SIGNEDMSG.append(m)
	SIGNEDMSG.append((c,s))
	return SIGNEDMSG


def get_constants(prefix):
    return dict( (getattr(socket, n), n)
                 for n in dir(socket)
                 if n.startswith(prefix)
                 )

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
    Portnum = int(input("Enter port number : "))
    families = get_constants('AF_')
    types = get_constants('SOCK_')
    protocols = get_constants('IPPROTO_')
    server_ip = sys.argv[1]
    try:
        sock = socket.create_connection((str(server_ip), Portnum))
    except socket.error:
        print( "failed to connect to server")
        sys.exit()
    print( "Socket connected to "+str(Portnum)+" on ip "+str(server_ip))
    create_socket_flag=0
    PUBKEY=[];q=0
    PUBKEY,privateA,q = keygen(PUBKEY)
    print( "\n")
    print( "Value of g:- ")
    print( PUBKEY[0])
    print( "\n")
    print( "Value of y1:- ")
    print( PUBKEY[1])
    print( "\n")
    print( "Value of y2:- ")
    print( PUBKEY[2])
    print( "\n")
    print( "Private key of A:- ")
    print( privateA)
    print( "\n")
    print( "value of q:- ")
    print( PUBKEY[3])
    print( "\n")
    send_data=str(PUBKEY[0])
    for i in range(1,len(PUBKEY)):
        send_data+=" "+str(PUBKEY[i])
    try:
        send_msg(sock,send_data)
    except socket.error:
        print( "Unable to send public elements to B")
        sys.exit()
    print( 'Public elements are sent to B\n')
    while True:
        if create_socket_flag==1:
            try:
                sock = socket.create_connection((server_ip,Portnum))
            except socket.error:
                print( "Failed to connect to server")
        msg = raw_input("Enter the binary message : ")
        print( "\n")
        print( "The input binary msg : ")
        print( msg)
        print( "\n")
        SIGNEDMSG=[]
        SIGNEDMSG = siggen(PUBKEY,privateA,str(msg),SIGNEDMSG,q)
        print( "Signed msg and signature tuple to be sent to B : ")
        print( SIGNEDMSG)
        print( "\n")
        send_data=str(SIGNEDMSG[0])+" "+str(SIGNEDMSG[1][0])+" "+str(SIGNEDMSG[1][1])
        try:
            send_msg(sock,send_data)
        except socket.error:
            print( "Unable to send signed msg to B")
            #sock.close()
            sys.exit()
        print( "Signed msg is sent to B\n")
        try:
            recv_data = recv_msg(sock)
        except socket.error:
            print( "Unable to receive verification status from B")
            #sock.close()
            sys.exit()
        print( "Received verification status from B\n")
        print( "Verification status send by B is : "+str(recv_data))
        #print( recv_data)
        print( "\n")
        if int(recv_data)==1:
            print( "Signature is verified by B")
        elif int(recv_data)==0:
            print( "Signature couldn't be verified by B")
        print( "\n")
        sock.close()
        if create_socket_flag==0:
            create_socket_flag=1