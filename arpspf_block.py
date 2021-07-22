import requests
import warnings
import re
from datetime import datetime
from datetime import timedelta
warnings.filterwarnings("ignore", message= "Unverified HTTPS request ")

# Import class with SmartZone API calls
#from vSZapi import vSZ_calls

# SmartZone variables
host = 'https://vsz-beta.ruckusdemos.net:8443'
username = "admin"
password = "J@ck7629!!!!"
domain = "OpenRoaming"
r = requests.Session()

#API version
response = r.get(host + '/wsg/api/public/apiInfo',verify=False).json()
print(response)
api_ver = response['apiSupportVersions'][2]
print(api_ver)

# Initializing global variables
token = None
domainID = None
zoneID = None
ievents=0
iblkmac=0
macpresent=0
pattern = None

#Get time now
currtime = datetime.now()
time3minago = currtime - timedelta(minutes = 3)
time3minago = (currtime - timedelta(minutes = 3)).strftime("%Y-%m-%d %H:%M:%S")

# Instantiate class
#mySmartZone = vSZ_calls()

#Get authentication token
response = r.post(host + '/wsg/api/public/'+ api_ver +'/serviceTicket', json={'username': username, 'password': password}, verify=False).json()
print(response)
serviceTicket = response['serviceTicket']
print(serviceTicket)
szver = response['controllerVersion']
print(szver)

#List Blocklist
blkresponse = r.post(host + '/wsg/api/public/'+ api_ver +'/blockClient/query?serviceTicket=' + serviceTicket, json={'filters': [],'fullTextSearch': {'type': 'AND','value': '','fields': ['eventCode']}},verify=False).json()
print(blkresponse)
totalblocked = blkresponse['totalCount']
print(totalblocked)

#Query Events
querylimit = 3 ##Dummy alert. Change to 100
response = r.post(host + '/wsg/api/public/'+ api_ver +'/alert/event/list?serviceTicket=' + serviceTicket, json={'filters': [],'fullTextSearch': {'type': 'AND','value': '236','fields': ['eventCode']},'sortInfo': {"sortColumn": "insertionTime","dir": "DESC"},"limit":querylimit},verify=False).json()
print(response)
totalevents = response['totalCount']

#Query Domains
domainresponse = r.get(host + '/wsg/api/public/'+ api_ver +'/domains/byName/' + domain + '?serviceTicket=' + serviceTicket, verify=False).json()
print(domainresponse)
domainID = domainresponse['list'][0]['id']

if totalevents==0: #Do not execute while loop
    icount = 0
    ievents = 1
elif querylimit<totalevents: #100<1-99 = false ; 100<100-infinity = true
    icount = querylimit #100-infinity
    ievents = 0
    print("Found ...", querylimit ," events happened last 3 min. Checking if any packet spoofing events present...")
else:
    icount = totalevents #1-99
    ievents = 0 
    print("Found ", totalevents ," events happened last 3 min. Checking if any packet spoofing events present...")
print("total filtered events", icount)

while ievents < icount:
    print("iteration", ievents)
    eventcode = response['list'][ievents]['eventCode']
    eventid = response['list'][ievents]['id']
    eventtype = response['list'][ievents]['eventType']
    eventtime1 = response['list'][ievents]['insertionTime']
    eventtime1 = int(eventtime1/1000)
    eventtime2 = datetime.fromtimestamp(eventtime1).strftime("%Y-%m-%d %H:%M:%S")
    eventdesc = response['list'][ievents]['activity']
    
    ###Dummy values alert
    eventtype='Packet spoofing detected'
    eventdesc="Packet spoofing detected [[Antispoof]DAI - ARP spoofing detected] from client [F4:96:34:AF:5C:3F@10.22.139.77] on WLAN [NITT] [wlan32] from AP [RuckusAP@34:20:E3:2D:19:A0]"
    ###

    if eventtime2 < time3minago: ####Dummy alert - Change < to > once dummy testing over
        if ((eventtype=='Packet spoofing detected') and (eventdesc.find('ARP spoofing') != -1)):
            print("Found recent packet spoofing incidents. Extracting details of offenders...")
            #Search for pattern and extract client mac
            pattern = "from client \[(.*?)\] on WLAN"
            substring1 = re.search(pattern, eventdesc).group(1)
            substring2 = substring1.split('@')
            clientmac = substring2[0]

            #Search for pattern and extract AP mac
            pattern = "from AP \[(.*?)\]"
            substring1 = re.search(pattern, eventdesc).group(1)
            substring2 = substring1.split('@')
            apmac = substring2[1]

            ###Dummy values alert
            clientmac="2A:0A:14:F3:55:70"
            domainID="cbfb00fb-55ae-4a1d-9921-7be7d4045119"
            ###
            print(clientmac)
            print(totalblocked)

            if(totalblocked > 0):
                    while iblkmac < totalblocked:
                        #if (clientmac == blkresponse['list'][iblkmac]['mac']):
                        if (clientmac == clientmac): #dummy alert
                            print(clientmac + "==" + blkresponse['list'][iblkmac]['mac'])
                            macpresent=1
                            print("MAC present")
                        iblkmac=iblkmac+1
            
            if(macpresent != 1):
                #Get more info about client - Username, hostname
                client_response = r.post(host + '/wsg/api/public/'+ api_ver +'/query/client?serviceTicket=' + serviceTicket, json={'filters': [{"type": "DOMAIN","value": domainID}],'fullTextSearch': {'type': 'AND','value': clientmac},'sortInfo': {"sortColumn": "clientMac","dir": "ASC"},"limit":1},verify=False).json()
                if client_response['totalCount']!=0:
                    udescription = "ARP Spoof User-" + client_response['list'][0]['userName'] + ";Host-" + client_response['list'][0]['hostname'] + ";"
                    udescription = udescription[:64]
                else:
                    udescription = "ARP Spoof"
                
                #Disconnect client
                deauth_response = r.post(host + '/wsg/api/public/'+ api_ver +'/client/deauth?serviceTicket=' + serviceTicket, json={'mac': clientmac,'apMac': apmac},verify=False).json()

                #Add client into blacklist
                block_response = r.post(host + '/wsg/api/public/'+ api_ver +'/blockClient/byApMac/' + apmac + '?serviceTicket=' + serviceTicket, json={'mac': clientmac, 'description': udescription},verify=False).json()

                #Print variables for log
                print("")
                print("New ARP spoof event occoured from now to 3min ago - Empty")
                print("Event iteration:", ievents+1)
                print("Event ID: ", eventid)
                print("Time: ", eventtime1)
                print("Desc: ", eventdesc)
                print("Type: ",eventtype)
                print("Code: ",eventcode)
                print("Client MAC+IP", str(substring2))
                print("Client MAC address", clientmac)
                print("AP MAC+IP", str(substring2))
                print("AP MAC address", apmac)
                print(udescription)
                print(deauth_response)
                print(block_response)
    ievents=ievents+1
print()
print("Total events:",totalevents, ", Filtered:", icount, ", Reported/Disconnected/Blocked:", iblkmac )
exit()