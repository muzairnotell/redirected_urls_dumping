
domain_freq_description = """
This endpoint fetch frequency of domain in suspicious db that how manay times it is repeated.\n
Example: How to pass domain to endpoint: \n
\n{\n
  "domain": "string",\n
  "matchinig_artifcats_from": 0,\n
  "matching_artifacts_upto": 100,\n
  "matching_artifacts_ful_len": false\n

\n}

"""


pcap_api_description = """
This endpoint is accepting pcap path with .zip extention and then download that pcap from data center then unzip file and then extract redirected urls and search their domains in suspicous domains if exist then return response. \n
Example: How to  pass pcap file path \n
\n{\n
  "pcap_path": "c4d648b827df08bf6fdef23ed6295ac398737f494c475138a61fc60b1d98ec76.zip"\n
\n}\n
"""


fix_fp_fn = """
This endpoint is used to correct false positives (FP) and false negatives (FN) in your list of malicious or benign artifacts. If you've identified an artifact as an FP or FN, you can move it to the appropriate list. Specifically, if an artifact is a false positive (FP), it will be moved to the benign list; if it's a false negative (FN), it will be moved to the malicious list.
\n
Example:\n
This endpoint expects the following input data:\n
\n
{\n
  \n"artifact_id": "string",
  \n"domain_name": "string",
 \n "flag": "fp or fn"
\n}
\n
artifact_id : The ID of the artifact you want to correct.\n
domain_name : The domain for which you want to correct the FP or FN.\n
flag : The flag indicating whether the artifact is a false positive ('fp') or a false negative ('fn').\n
"""

matching_bulk_api = """
This endpoint returns batches of matching artifacts for specific domains.\n

Example:\n

{\n
  "domain_name": "dan.com"\n
}\n

- domain_name: The domain for which you want to retrieve matching artifact batches.\n
"""
remove_potential_fn_id_api = """
This endpoint removes an artifact ID from the potential FNs list after it has been fixed.
\n
Example:\n

{\n
  \n"domain_name": "dan.com",
  \n"artifact_id": "c08e18592dc9e7f5ab5bed3b378ee8cc3edfc7dd5082b7283da04ae6e6c9a379"
\n}
\n
- domain_name: The domain from which you want to remove a specific ID from the potential FNs list.
\n- artifact_id: The ID you want to remove.\n
"""