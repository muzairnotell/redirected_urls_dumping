
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.layers import http
import re
import os 
import json 
import requests
from multiprocessing import Pool
 

def human_readable_payload(packet):
    """
    This method will return payload in human readable formate
    """
    readable_payload = None
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
    
            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load
        
                try:
                    readable_payload = raw_payload.decode('ascii')
                    return readable_payload
                except UnicodeDecodeError:
                    readable_payload = raw_payload.decode('utf-8', errors='replace')
                    return readable_payload
         
            else:
                return None 
   
        else:
            return None
    except Exception as e:
        print(e)
        return None



def extract_packet_info(packet, path):
    """
    This method is extracting all information from packets.
    """
    try:
 
        redirect_urls = []
        status_code = []
 
        file_name = os.path.basename(path)

        if packet.haslayer(http.HTTPResponse):

            # redirected urls are in range of 300 - 399
            if 300 <= int(packet[http.HTTPResponse].Status_Code) < 400:
                location = packet[http.HTTPResponse].fields.get('Location')
                if isinstance(location, bytes):
                    location = location.decode('utf-8')
                status_code.append(int(packet[http.HTTPResponse].Status_Code))
                redirect_urls.append(location)
     
        if '_https' in file_name:

            response = human_readable_payload(packet)
            if response is not None:
                match = re.search(r'<!--\s*Redirected URL:\s*(https?://[^\s]+)\s*-->', response)
                
                if match:
                    url = match.group(1)
                    if url:
                        redirect_urls.append(url)
                        pattern = r"<!--\s*Redirected URL status code:\s*(\d+)\s*-->"
                        status_code_match = re.search(pattern, response)
                        if status_code_match:
                            status_code.append(status_code_match.group(1))

        if len(redirect_urls) == 1:
            redirect_urls = redirect_urls[0]
        
        if redirect_urls == []:
            redirect_urls = None
            
        if len(status_code) == 1:
            status_code = status_code[0]
        
        if status_code == []:
            status_code = None
        resposne = {"path" : path, "redirected_url" : redirect_urls, "status_code" : status_code}

        return resposne
    
    except Exception as e:
        print("Error in extract_packet_info: ", e)
        redirect_urls = None 
        status_code = None
        return {"path" : path, "redirected_url" : redirect_urls, "status_code" : status_code}



def process_pcap_file(path):

    """
    this method is processing pcap file
    """
    try:

        # read pcaps
        packets = rdpcap(path)

        packet_data = []
        for packet in packets:
            response = extract_packet_info(packet, path)
    
            if response['redirected_url'] is not None:
                # remove localhost urls
                is_lh = is_local_host(response['redirected_url'])
                
                if  is_lh is False:
                    domain = extract_clear_domain(response['redirected_url'])
                    response['domain'] = domain
                
                    packet_data.append(response)
        return packet_data
    
    except Exception as e:
        print(f"Error in process_pcap_file : {traceback.format_exc()}")
        return ''

import time 


def is_local_host(url):


    """ 
    This method is finding localhost urls and remove it from data.
    """
    try:
        local_host_patterns = [
            r'http://localhost',
            r'http://127\.0\.0\.1',
            r'http://192\.168\.\d{1,3}\.\d{1,3}',  # For local network IPs
            r'http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Another range for local network IPs
            r'http://172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}'  # For 172.16.0.0 to 172.31.255.255
        ]
        for pattern in local_host_patterns:
            if re.match(pattern, url):
                return True
        return False
    except Exception as e:
        return False
        print(f"Error in is_local_host method : {e}")
    
def extract_clear_domain(url):
    """ 
    Remove protocol and paramters from urls just get domains.
    """

    try:
        match = re.match(r'(?:https?://)?(?:www\.)?([^/]+)', url)
        if match:
            return match.group(1)
        else:
            return None
    except Exception as e:
        print(f"Error in extract_clear_domain {e}")
        return None 


def process_file_wrapper(path):
    return process_pcap_file(path)


def get_pcap_data():
    try:
        print("Get pcap called....")
        paths = "/disk0/suspicious-domains-endpoints/code/pcaps/extracted_pcaps/"
        files = [os.path.join(paths, file) for file in os.listdir(paths)]
        redirected_urls = []

        with Pool() as pool:
            results = pool.map(process_file_wrapper, files)

        for path, response in zip(files, results):
            redirected_urls.append(response)

        return redirected_urls

    except Exception as e:
        print(f"Error in get_pcap_data: {e}")
        return []