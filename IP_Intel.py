import requests
import csv

def virustotal(IP, KEY,input):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"

    headers = {
        "accept": "application/json",
        "x-apikey": KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        r = response.json()

        country = r["data"]["attributes"]["country"]
        reputation = r["data"]["attributes"]["last_analysis_stats"]["malicious"]
        org = r["data"]["attributes"]["as_owner"]

        if(input=='M'):
            values.extend([IP,reputation,country,org])
        
        else:
            print("Virus Total Report","\n")
            print(f"\033[93mVirusTotal Reputation: {reputation}\033[0m")
            print(f"Country: {country}")
            print(f"Org: {org}")

            if reputation != 0:
                print("\n")
                print("\033[93mLast analysis results:\033[0m")
                for engine_name, result_info in r["data"]["attributes"]["last_analysis_results"].items():
                    if(result_info['result'] not in ['unrated', 'clean']):
                        print(f"{engine_name}: \033[91m{result_info['result']}\033[0m")
    else:
        print(f"Error: {response.status_code}. Failed to retrieve information.")


def absuseIP(IP, KEY,input):

    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': IP
    }

    headers = {
        'Accept': 'application/json',
        'Key': KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    r = response.json()
    date = r["data"]["lastReportedAt"]

    if(input=='M'):
        values.extend([r["data"]["abuseConfidenceScore"],r["data"]["isPublic"],r["data"]["domain"],r["data"]["isTor"],r["data"]["isp"]])
    else:

        print("AbuseIP Report", "\n")
        print(f"\033[93mAbuseConfidenceScore: {r['data']['abuseConfidenceScore']}\033[0m")
        print(f"Domain: {r['data']['domain']}")
        print(f"ISP: {r['data']['isp']}")

        if date is not None:
            date, time = date.split('T')
            print(f"Last Reported: {date} {time}")

        print("Public IP:", '\033[92mTrue\033[0m' if {r["data"]["isPublic"]} else '\033[91mFalse\033[0m')
        print("Tor IP:", '\033[92mTrue\033[0m' if {r["data"]["isTor"]} else '\033[91mFalse\033[0m')

def ipinfo(IP,KEY,input):

    url = f'https://ipinfo.io/{IP}?token={KEY}'
    response = requests.get(url)

    if(response.status_code==200):

        r = response.json()

        if(input=='M'):
            values.extend([r["region"],r["timezone"]])

        else:
            print("IPInfo Report","\n")
            print(f"City: {r['city']}")
            print(f"Region: {r['region']}")
            print(f"Country: {r['country']}")
            print(f"Org: {r['org']}")
            print(f"TimeZone: {r['timezone']}")

    else:
        print(f"Error: {response.status_code}. Failed to retrieve information.")

def ipdata(IP,KEY,input):

    url = f'https://api.ipdata.co/{IP}?api-key={KEY}'
    response = requests.get(url)

    if(response.status_code==200):
        
        r=response.json()
        if(input=='M'):
            values.extend([r['asn']['asn'],r['threat']['is_icloud_relay'],r["threat"]["is_datacenter"],r["threat"]["is_bogon"]])
        else:   
            carrier= r.get("carrier")
            print("IPdata Report","\n")
            print(f"City: {r['city']}")
            print(f"Region: {r['region']}")
            print(f"Country: {r['country_name']}")
            print(f"ASN: {r['asn']['asn']}")

            if carrier is not None:
                print(f"Carrier: {r['carrier']['name']}")	
            else:
                print(f"Carrier: {carrier}")	

            #Threat Intel
            print("Tor IP:", '\033[92mTrue\033[0m' if r['threat']['is_tor'] else '\033[91mFalse\033[0m')
            print("Proxy IP:", '\033[92mTrue\033[0m' if r['threat']['is_proxy'] else '\033[91mFalse\033[0m')
            print("Apple's iCloud relay service:", '\033[92mTrue\033[0m' if r['threat']['is_icloud_relay'] else '\033[91mFalse\033[0m')
            print("Attacks, malware, botnet IP:", '\033[92mTrue\033[0m' if r['threat']['is_known_attacker'] else '\033[91mFalse\033[0m')
            print("Spam, harvesters, registration bots IP:", '\033[92mTrue\033[0m' if r['threat']['is_known_abuser'] else '\033[91mFalse\033[0m')
            print('Data Centre IP:', '\033[92mTrue\033[0m' if r["threat"]["is_datacenter"] else '\033[91mFalse\033[0m', "(Data center IPs are owned by hosting and cloud service providers,not ISPs)")
            print('Bogon IP:', '\033[92mTrue\033[0m' if r["threat"]["is_bogon"] else '\033[91mFalse\033[0m', "(Reserved private IPs that are not supposed to be publicly routable)")

    else:
        print(f"Error: {response.status_code}. Failed to retrieve information.")

def ipquality(IP,KEY,input):
    url=f'https://www.ipqualityscore.com/api/json/ip/{KEY}/{IP}?strictness=0&allow_public_access_points=true'
    response=requests.get(url)

    if(response.status_code==200):
        r=response.json()
        if(input=='M'):
            values.extend([r['fraud_score'],r['is_crawler']])

        else:
            print("IPQualityScore Report","\n")
            print(f"\033[93mIP Quality Score: {r['fraud_score']} \033[0m (75+ as suspicious and 90+ as high risk)")
            print(f'City: {r["city"]}')
            print("Crawler:", '\033[92mTrue\033[0m' if r['is_crawler'] else '\033[91mFalse\033[0m')
            print("Proxy IP:", '\033[92mTrue\033[0m' if r['proxy'] else '\033[91mFalse\033[0m')
            print("VPN IP:", '\033[92mTrue\033[0m' if r['vpn'] else '\033[91mFalse\033[0m')

    else:
        print(f"Error: {response.status_code}. Failed to retrieve information.")

def vpnapi(IP,KEY,input):
	
	url = f'https://vpnapi.io/api/{IP}?key={KEY}'
	response = requests.get(url)

	if(response.status_code==200):
		r=response.json()
		
		if(input=='M'):
			values.extend([r['security']['vpn'],r['security']['proxy']])

		else:    
			print("VPNAPI Report","\n")
			print("Proxy IP:", '\033[92mTrue\033[0m' if r['security']['proxy'] else '\033[91mFalse\033[0m')
			print("VPN IP:", '\033[92mTrue\033[0m' if r['security']['vpn'] else '\033[91mFalse\033[0m')
	else:
		print(f"Error: {response.status_code}. Failed to retrieve information.")

VT_KEY="Enter Your VirusTotal API Key"
ABUSE_KEY="Enter Your AbuseIP API Key"
IPINFO_KEY ="Enter Your IPInfo API Key"
IPDATA_KEY = "Enter Your IPData API Key"
IPQUALITY_KEY ="Enter Your IPQualityScore API Key"
VPNAPI_KEY = "Enter Your VPNAPI API Key"

user_input=input("Single(S) IP or Muliple IP's(M):")

if(user_input=='S'):
    
    IP=input("Enter IP: ")
    values=[]
    print("=====================================================================")
    print(f"\033[93mIP Address:{IP}\033[0m")
    print("=====================================================================")
    ipinfo(IP,IPINFO_KEY,user_input)
    print("=====================================================================")
    ipdata(IP,IPDATA_KEY,user_input)
    print("=====================================================================")
    virustotal(IP,VT_KEY,user_input)
    print("=====================================================================")
    absuseIP(IP,ABUSE_KEY,user_input)
    print("=====================================================================")
    ipquality(IP,IPQUALITY_KEY,user_input)
    print("=====================================================================")
    vpnapi(IP,VPNAPI_KEY,user_input)
    print("=====================================================================")

elif(user_input=='M'):

    with open('combined_report.csv', 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        headers = ["IP", "VirusTotal Reputation","Country","Org","AbuseConfidenceScore","Public IP","Domain", "Tor IP", "ISP","Region","Time-Zone","ASN","ICloud relay IP","Data Centre IP","Bogon IP","IPQualityScore","Crawler IP","VPN","Proxy"]
        csv_writer.writerow(headers)

    ip_addresses=[]
    with open('multi_IP.txt','r') as file:
        for ip in file:
            ip_addresses.append(ip.strip())

    
    for IP in ip_addresses:
        # Open the file and write headers only once
        values=[]
        print(f"Running Reports for {IP} ...")
        virustotal(IP,VT_KEY,user_input)
        absuseIP(IP,ABUSE_KEY,user_input)
        ipinfo(IP,IPINFO_KEY,user_input)
        ipdata(IP,IPDATA_KEY,user_input)
        ipquality(IP,IPQUALITY_KEY,user_input)
        vpnapi(IP,VPNAPI_KEY,user_input)
        with open('combined_report.csv', 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile) 
            csv_writer.writerow(values)
        
else:
    print("Enter Valid Choice")
