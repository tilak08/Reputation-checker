
#------------------------------------------------------------------------
#ipreputation_checker
import csv
import requests
import json
import requests
from time import sleep
import pandas as pd

def ipreputation_main():

      
    # Counter variable used for writing  
    # headers to the CSV file 
    count = 0
    #API_KEY =   "1cca5d49ddcc66c5c889bff0d6afcb66ee5c75a3"
    API_KEY = str(input("enter the API key"))
    with open("ip.txt") as fp:
        data=fp.readlines()
    API_URL =   "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key="+API_KEY+"&ip="
    ipdata = []

    with open('ipreputation.csv','w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for ip in data:
            ip  =   ip.rstrip()
            url =   API_URL+ip
            response    =   requests.get(url)
            jsonData    =   response.json()
            reportData  =   jsonData['data']["report"]["blacklists"]["engines"]
            report_df = pd.DataFrame.from_dict(reportData,orient='index')
            report_df['ip'] = ip
            writer.writerow([ip] + report_df['detected'].tolist())


        




#--------------------------------------------------------------------------
#domain_scanner
import csv
import requests
import json
import requests
from time import sleep
import pandas as pd
def domain_main():

    data_file = open('domainreputation.csv', 'w') 
      
    # create the csv writer object 
    csv_writer = csv.writer(data_file) 
      
    # Counter variable used for writing  
    # headers to the CSV file 
    count = 0
    #API_KEY =   "1cca5d49ddcc66c5c889bff0d6afcb66ee5c75a3"
    API_KEY = str(input("enter the API key"))
    with open("domains.txt") as fp:
        data=fp.readlines()
    API_URL =   "https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key="+API_KEY+"&host="
    domaindata = []
    
    with open('domain.csv','w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for domain in data:
            domain = domain.rstrip()
            url = API_URL+domain
            response    =   requests.get(url)
            jsonData    =   response.json()
            reportData  =   jsonData['data']["report"]["blacklists"]["engines"]
            report_df = pd.DataFrame.from_dict(reportData, orient= 'index')
            report_df['domain'] = domain
            writer.writerow([domain] + report_df['detected'].tolist())

#----------------------------------------------------------------------
#hash checker program
import requests
import time
import csv
import sys
def hash_main():
    class GetOutOfLoop( Exception ):
        pass
        
    def getdata(hash,apikey):
        params = {'apikey': apikey, 'resource':hash}
        headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
        response_dict={}
        try:
            r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            if r.status_code == 403:
                return "Forbidden. You don't have enough privileges to make the request"
            elif  r.status_code == 204:
                return "Request rate limit exceeded"
            elif r.status_code == 400:
                return "Bad Request"
            elif r.status_code == 200:
                response_dict = r.json()
                return response_dict
        except Exception as e:
            return "API Request Error"
        return response_dict
        
        
    with open('hashes.txt', 'r+') as f:
        lines = [line.rstrip('\n') for line in open('hashes.txt')]

    with open('apikeys.txt', 'r') as f:
        apikeys = [line.rstrip('\n') for line in open('apikeys.txt')]
    if len(apikeys) <= 14 :
        waitime = (60 - len(apikeys) * 4)
    else:
        waitime = 3
    csv_handle=open('output.csv','w')

    flag=0
    el_flag=True
    print("This is a Virustotal Checker The output will be loaded into output.csv")
    print("Total no.of api keys added "+str(len(apikeys))+" And the calculated wait time is "+str(waitime))
    print("Total no.of hashes loaded is :"+str(len(lines)))
    hashes = iter(lines)
    unprocessed=[]
    notinvt=[]
    count=0
    try:
        while el_flag:
            for api_key in apikeys:
                for i in range(0,4):
                    response_dict={}
                    hash=""
                    count=count+1
                    try:#getting hashes from iterator
                        hash = next(hashes)
                    except:
                        print("End of list")
                        el_flag=False
                        raise GetOutOfLoop
                    response_dict=getdata(hash,api_key)
                    sample_info={}
                    if isinstance(response_dict, str):
                        #print("request error for hash :"+hash)
                        print("-->"+response_dict+" for Hash "+hash)
                        if response_dict == "Request rate limit exceeded":
                            print("Changing api key..")
                            unprocessed.append(hash)
                            break
                    elif isinstance(response_dict,dict) and response_dict.get("response_code") == 0:
                        #print("Not in VT for hash :"+str(hash))
                        notinvt.append(hash)
                    elif isinstance(response_dict,dict) and response_dict.get("response_code") == -2:
                        print("In queue for scanning")
                    elif isinstance(response_dict,dict) and response_dict.get("response_code") == 1:
                        # Hashes
                        sample_info["md5"] = response_dict.get("md5")
                        # AV matches
                        sample_info["positives"] = response_dict.get("positives")
                        sample_info["total"] = response_dict.get("total")
                        csv_handle.write(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
                        print(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"])+"-->"+str(count),end = '\n')
                        csv_handle.write('\n')
                    else:
                        print("Unknown Error for hash "+hash)
                        unprocessed.append(hash)
                print("Api Key has ran 4 times.. Changing APi Key..\n")
            print("WaitTime is "+str(waitime)+" Seconds")
            for i in range(1,waitime):
                print(i,end="\r")
                time.sleep(1)
    except GetOutOfLoop:
        csv_handle.close()
    print("unprocessed hashes "+str(unprocessed ))
    print("Hashes in Not in VT"+str(notinvt))



#------------------------------------------------------------------- 


def user_menu():
    print("welcome to the reputation checker program....")
    print("the user menu is as follows.")
    print("option 1: IP reputation checker")
    print("option 2: Domain name reputation checker")
    print("option 3: Hash value reputation checker")
    
    option=input("enter the option (1,2 or 3) that has to be chosen:")

    if option=="1":
        print("now calling the IP reputation function....")
        ipreputation_main()

    elif option=="2":
        print("now calling the domain reputation function....")
        domain_main()
       
    elif option=="3":
        print("now calling the hash function....")
        hash_main()
    else:
        print("incorrect option. try again")
        user_menu()
        
user_menu()        

