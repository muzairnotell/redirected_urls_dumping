from fastapi import FastAPI, HTTPException
from schema import DomainFrequency, PcapPath, DomainFrequencyResponse, ProcessPcapResponse, FixFPFNArtifacts, MatchingArtifacts, MatchingBulks, Potential_FNs
from extract_zip import extract_zipfile
from fastapi import FastAPI
from query import CRUD
from pcap_processing import get_pcap_data
import traceback
import subprocess
import os
import json 
from typing import List, Dict
import time
import threading
import shlex 
from pcap_processing import extract_clear_domain
from apis_expalaination import *
from pprint import pprint
from utility import *
app = FastAPI()

crud = CRUD()
@app.get("/")
def read_root():
    return {"Hello": "Welcome to suspicious domains application"}

@app.post('/domain_frequency', response_model=DomainFrequencyResponse, description=domain_freq_description)
def get_frequency(data: DomainFrequency):
    try:
        matching_artifacts = {'malicious_artifacts': [], 'benign_artifacts': []}

        if data.domain is not None:
            response = crud.search_domain(data.domain)
            if response is not None:
                file_path = f"/disk0/suspicious_domains_extractions/pcaps-data-extraction/{response['file_path']}"
                bulks_path = f"/disk0/suspicious_domains_extractions/pcaps-data-extraction/{response['matching_artifacts_bulk']}"
                filename = os.path.splitext(os.path.basename(response['file_path']))
                id = filename[0]

                # Dictionary to store loaded data
                loaded_data = {}

                # Function to load file data
                def load_file(file_key, file_path):
                    if os.path.getsize(file_path) > 0:
                        with open(file_path, 'r') as file:
                            loaded_data[file_key] = json.load(file)

                # Create and start threads for loading files in parallel
                file_thread = threading.Thread(target=load_file, args=('hashes', file_path))
                bulks_thread = threading.Thread(target=load_file, args=('bulks', bulks_path))

                file_thread.start()
                bulks_thread.start()

                # Wait for both threads to complete
                file_thread.join()
                bulks_thread.join()

                # Retrieve the loaded data
                hashes = loaded_data.get('hashes', {})
                bulks = loaded_data.get('bulks', {})

                # Process the loaded data
                if id in hashes:
                    matching_artifacts['malicious_artifacts'] = hashes[id]
                if f'{id}_benign' in hashes:
                    matching_artifacts['benign_artifacts'] = hashes[f'{id}_benign']

                # Handle cases where starting point is greater than ending point
                if data.matchinig_artifcats_from > data.matching_artifacts_upto:
                    data.matchinig_artifcats_from, data.matching_artifacts_upto = data.matching_artifacts_upto, data.matchinig_artifcats_from

                if not data.matching_artifacts_ful_len:
                    # Get n elements from matching artifacts
                    matching_artifacts['malicious_artifacts'] = matching_artifacts['malicious_artifacts'][data.matchinig_artifcats_from:data.matching_artifacts_upto+1]
                    matching_artifacts['benign_artifacts'] = matching_artifacts['benign_artifacts'][data.matchinig_artifcats_from:data.matching_artifacts_upto+1]

                response['matching_artifacts'] = matching_artifacts
                response['bulks'] = bulks

            return response
        else:
            raise HTTPException(status_code=404, detail="Domain with this name not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in get_frequency endpoint: {e}")


@app.post('/fix_fpfn_artifacts', description=fix_fp_fn)
def fix_fpfn_records(data : FixFPFNArtifacts):
    
    result = {}
    try:
        response = crud.search_domain(data.domain_name)
        if response is not False:
            print(f"file path : {response['file_path']}")
            file_path = f"/disk0/suspicious_domains_extractions/pcaps-data-extraction/{response['file_path']}"

            with open(file_path, 'r') as file:
                json_data = json.load(file)
                
                for key, value in json_data.items():
                    print(f"len {key} : {len(value)}")
            
            index_name = os.path.splitext(os.path.basename(file_path))[0]
            print(f"index_name : {index_name}")
            if data.flag.lower() == 'fp':
                json_data[index_name].remove(data.artifact_id)
                json_data[f'{index_name}_benign'].append(data.artifact_id)
                result["response"] = 'file updated'
                print("value removed from malicous list and added in benign")
                print(f"len ==> {len(json_data[f'{index_name}_benign'])}")
                print(f"len ==> {len(json_data[f'{index_name}'])}")

                with open(file_path, 'w') as file:
                    json.dump(json_data, file, indent=4)
                crud.update_frequencies(data.domain_name, data.flag)
            elif data.flag.lower() == 'fn':
                json_data[f'{index_name}_benign'].remove(data.artifact_id)
                print(f"len ==> {len(json_data[f'{index_name}_benign'])}")
                json_data[index_name].append(data.artifact_id)
                result["response"] = 'file updated'
                print("value removed from benign and added in malcious list.")
                # os.makedirs(response['file_path'], exist_ok=True)
                with open(file_path, 'w') as file:
                    json.dump(json_data, file, indent=4)
                crud.update_frequencies(data.domain_name, data.flag)

            else:
                result['response'] = 'flag value must be fp or fn not accepting any other value'
            return result
        else:
            print("This domain dose not exist in db.")

    except Exception as e:
        print(f"Exception state, {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Exception occured : {e}")


@app.post('/matching_bulks', description=matching_bulk_api)
def get_matching_bulks(data: MatchingBulks):
    
    bulk_data = {}
    try:
        document = crud.search_domain(data.domain_name)
        print('document : ', document.keys())
        if document is not None:
            file_path = document.get('matching_artifacts_bulk', None)
            print(file_path)
            if file_path is not None:
                root = '/disk0/suspicious_domains_extractions/pcaps-data-extraction/'
                path = f"{root}{file_path}"

                with open(path, 'r') as file:
                    bulk_data = json.load(file)
                
                return bulk_data
            else:
                raise HTTPException(status_code=500, detail= f"File path is None")

        else:
            raise HTTPException(status_code=404, detail= f"Document not found with {data.domain_name}.")
    except Exception as e:
        raise HTTPException(status_code=500, detail = f"Error in get_matching_bulks : {e}")
    

@app.post('/remove_potential_fn_id', description=remove_potential_fn_id_api)
def remove_id_from_potential_FNs(data : Potential_FNs):
    response = None
    try:
        document = crud.search_domain(data.domain_name)
        if document is not None:
            
            file_path = document.get('matching_artifacts_bulk', None)
            if file_path is not None:
                root = '/disk0/suspicious_domains_extractions/pcaps-data-extraction/'
                path = f"{root}{file_path}"

                with open(path, 'r') as file:
                    bulk_data = json.load(file)
                # potential_FNs = bulk_data.get('potential_fns', [])
                bulk_data.get('potential_fns', []).remove((data.artifact_id))
                with open(path, 'w') as file:
                    json.dump(bulk_data, file, indent=4)
                response = f"{data.artifact_id} is removed from potential FNs list" 
                return response
            else:
                raise HTTPException(status_code=500, detail=f"File path is None.")
        else:
            raise HTTPException(status_code=400, detail=f"Document not found with {data.domain_name}.")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in remove_id_from_potential_FNs : {e}")

@app.post('/process_pcap', description=pcap_api_description)
def check_pcap_by_db_date(pcap : PcapPath):

    try:
        now = time.time()

        # print("check_pcap called ... ")
        suspicous_domains_results = {}
        if pcap.pcap_path is not None:

            command1 = "find /disk0/suspicious-domains-endpoints/code/pcaps/zip_pcaps -type f -delete"
            command2 = "find /disk0/suspicious-domains-endpoints/code/pcaps/extracted_pcaps -type f -delete"

            # Create threads for each command
            thread1 = threading.Thread(target=run_command, args=(command1,))
            thread2 = threading.Thread(target=run_command, args=(command2,))

            # Start the threads
            thread1.start()
            thread2.start()

            # Wait for both threads to complete
            thread1.join()
            thread2.join()

            pcap_id = pcap.pcap_path.split('.')[0]
            score, created_date = crud.get_score_and_date(pcap_id)
            # redirected_urls['score'] = score
            created_date = created_date.split('T')[0].split('-')
 
            # SSH settings for the remote machine
            ssh_user = 'sk'
            ssh_host = '188.40.148.245'
            ssh_password = 'CyberNova!)@('
            # local_path = '/home/muxair/Desktop/suspicious_endpoints/pcaps/zip_pcaps/'
            local_path = '/disk0/suspicious-domains-endpoints/code/pcaps/zip_pcaps/'
            # # Define the combined command as a single string
                
            remote_path = f'/mnt/farm/{created_date[0]}/{created_date[1]}/{created_date[2]}/{pcap.pcap_path}'
            # print(f"remote path : {remote_path}")
                
            # # Check if the command was successful
            if created_date is not None:
                # print("file found.....")
                copy_pcap_cmd = f"sshpass -p '{ssh_password}' scp -r {ssh_user}@{ssh_host}:{remote_path} {local_path}"
                #    copy_pcap_cmd = f"sshpass -p '{ssh_password}' scp -r {ssh_user}@{ssh_host}:{result.stdout.strip()} {local_path}"
                                
                response = subprocess.run(copy_pcap_cmd, capture_output=True, text=True,  shell=True)
                if response.returncode == 0:
                    
                    pcap_path = local_path+pcap.pcap_path

                    extract_zipfile(pcap_path)
                    redirected_urls = get_pcap_data()
                    urls_list = set()
                    domains = set()
                    
                    for redirected_url in redirected_urls:
                        
                        for url in redirected_url:
                            if isinstance(url['redirected_url'], list):
                                urls_list.add(url['redirected_url'])
                                domains.add(url['domain'])

                            else:
                                urls_list.add(url['redirected_url'])
                                domains.add(url['domain'])


                    suspicous_domains_results['urls'] =  list(urls_list)
          

                    for domain in domains:
                        # print(f"Domain : {domain}")
                        response = crud.search_domain(domain)
                        # print("response : ", response)
                        if response is not None:
                            suspicous_domains_results[domain] = response

                    print(f"Time taken : {time.time() - now}")
                    return suspicous_domains_results

                else:
                    print("http exception called.")
                    # Print an error message
                    raise HTTPException(status_code=500, detail=f"File not found with this id.")
                
            else:
                raise HTTPException(status_code=400, detail=f"pcap with thiss Id not found.")


    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in check_pcap endpoint : {traceback.format_exc()}")

import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8108, reload=True)


