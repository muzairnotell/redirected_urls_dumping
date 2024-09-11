# my_dict = {"a" : [1,2,3,4,5,6,7],
# "b" : [8,9,10]}

# print(f"my dict : {my_dict}")

# my_dict['a'].remove(7)
# my_dict['b'].append(7) 
# print(f"updated mydict : {my_dict}")
import requests
# body = {
#     "domain": 'dan.com',
#     "matchinig_artifcats_from": 0,
#     "matching_artifacts_upto": 100,
#     "matching_artifacts_ful_len": True
#     }
                
# response = requests.post('http://95.216.65.25:8108/domain_frequency', json=body)
                
# if response.status_code == 200:
#     response = response.json()
#     matching_artifacts = []
#     matching_artifacts.append(response['matching_artifacts']['malicious_artifacts'])
#     matching_artifacts.append(response['matching_artifacts']['benign_artifacts'])
#     print("len ", len(matching_artifacts))

# body = {
#     "frequency" : 15000
# }

# url  = "http://95.216.65.25:8100/create_matching_bulks"
# print("called ... ")
# response = requests.post(url, json=body)
# print(response)
from pprint import pprint
from create_matching_bulks import SD_Classification
obj = SD_Classification()
print("Method called ....")
if __name__ == '__main__':
    results = obj.return_matching_clusters(20000)
    print('------------')
    pprint(len(results))