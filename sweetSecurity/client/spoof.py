import sqlite3
import logging
import threading

from time import sleep
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import sweetSecurityDB
dbPath="/opt/sweetsecurity/client/db/SweetSecurity.db"

def convertMAC(mac):
	newMac="%s%s:%s%s:%s%s:%s%s:%s%s:%s%s" % (mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],mac[6],mac[7],mac[8],mac[9],mac[10],mac[11])
	return newMac

def getMac():
	myMac = [get_if_hwaddr(i) for i in get_if_list()]
	for mac in myMac:
		if(mac != "00:00:00:00:00:00"):
			return mac

def spoofSingleDevice(dfgwMAC, dfgw, victimMac, victimIp, logger):
	try:
		logger.info("Spoofing Device: ip=%s, mac=%s",victimIp,victimMac)
        	#Spoof the things...
		victimMac=convertMAC(victimMac)
		packet = Ether()/ARP(op="who-has",hwdst=dfgwMAC,pdst=dfgw,psrc=victimIp)
		sendp(packet)
		packet = Ether()/ARP(op="who-has",hwdst=victimMac,pdst=victimIp,psrc=dfgw)
		sendp(packet)
	except Exception,e:
		logger.info("Error spoofing device: %s" % str(e))

def start():
	logger = logging.getLogger('SweetSecurityLogger')
	while 1:
		try:
			dfgwInfo=sweetSecurityDB.getDfgw()
			dfgw=dfgwInfo['dfgw']
			dfgwMAC=dfgwInfo['dfgwMAC']
			dfgwMAC=convertMAC(dfgwMAC)
			conn = sqlite3.connect(dbPath)
			c = conn.cursor()
			for row in c.execute('SELECT * FROM hosts where active = 1 and ignore = 0 order by MAC'):
				victimMac=row[3]
				victimIp=row[2]
				threading.Thread(target=spoofSingleDevice, args=(dfgwMAC, dfgw, victimMac, victimIp, logger)).start()
			conn.close()
			#sleep(1)
		except Exception,e: 
			logger.info("Error in spoofing thread: %s" % str(e))
