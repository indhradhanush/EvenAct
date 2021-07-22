import requests
import warnings
import json
import re
# Import date and timdelta class
# from datetime module
from datetime import datetime
from datetime import timedelta
warnings.filterwarnings("ignore", message= "Unverified HTTPS request ")

host = 'https://vsz-beta.ruckusdemos.net:8443'
username = "admin"
password = "J@ck7629!!!!"
r = requests.Session()

#Get authentication token
response = r.post(host + '/wsg/api/public/v10_0/serviceTicket', json={'username': username, 'password': password}, verify=False).json()
print(response)
serviceTicket = response['serviceTicket']
print(serviceTicket)
szver = response['controllerVersion']
print(szver)

#Query Domains
response = r.get(host + '/wsg/api/public/v10_0/domains/byName/API_Karthik?serviceTicket=' + serviceTicket, verify=False).json()
print(response)
domaincount = response['totalCount']
print(domaincount)
domainIdenti = response['list'][0]['id']
print(domainIdenti)
domainName = response['list'][0]['name']
print(domainName)

#Query RKSZones
response = r.get(host + '/wsg/api/public/v10_0/rkszones?serviceTicket=' + serviceTicket + '&domainId=' + domainIdenti, verify=False).json()
print(response)
totalzones = response['totalCount']
print(totalzones)
if totalzones!=0:
	zoneid = response['list'][0]['id']
	print(zoneid)
else:
	print("No Zones")

#List Blocklist
response = r.post(host + '/wsg/api/public/v10_0/blockClient/query?serviceTicket=' + serviceTicket, json={'filters': [],'fullTextSearch': {'type': 'AND','value': '','fields': ['eventCode']}},verify=False).json()
print(response)
totalevents = response['totalCount']
print(totalevents)

#Get time now and 24 hours ago
currtime = datetime.now()
today = currtime.strftime("%Y-%m-%d %H:%M:%S")
print("Today: ", today)
yday24hrs_ago = (currtime - timedelta(minutes = 1)).strftime("%Y-%m-%d %H:%M:%S") ##Dummyalert timedelta should be hours=24
print("Yday: ", yday24hrs_ago)


#for i in response['list']:
blockid=response['list'][0]['id']
print(blockid)
clientmac=response['list'][0]['mac']
print(clientmac)
datemac = response['list'][0]['modifiedDateTime']
print(datemac)
datemac=int(datemac/1000)
print(datemac)
datemac2 = datetime.fromtimestamp(datemac).strftime("%Y-%m-%d %H:%M:%S")
print(datemac2)
print(yday24hrs_ago)
if yday24hrs_ago > datemac2:
	print("deleteall")
	response = r.delete(host + '/wsg/api/public/v10_0/blockClient/' + blockid + "?serviceTicket=" + serviceTicket, json={'mac': clientmac}, verify=False).json()
else:
	print("End of line")
#2021/04/14 00:38:39 and 2020/11/23 15:46:37



#API version
response = r.get(host + '/wsg/api/public/apiInfo', json={'filters': [],'fullTextSearch': {'type': 'AND','value': '','fields': ['eventCode']}},verify=False).json()
print(response)
#totalevents = response['totalCount']
#print(totalevents)
