from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
production = True
load_dotenv()
FINGUREPRINT = os.getenv('DB_FINGERPRINT')
DB_NAME = os.getenv('DB_NAME')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_URL = os.getenv('DB_URL')

# connection with remote db
def get_elastic_client():
    if production:
        try:
            # fingerprint = ("F4:A2:C0:28:00:65:CE:EE:3D:F9:FD:6E:41:00:0B:2C:ED:89:17:64:B1:8D:0D:24:F0:84:30:5A:D0:04"
            #                ":58:64")
            # es = Elasticsearch(["https://95.216.43.163:9200"], http_auth=("elastic", "PufferFish!)@("),
            #                    ssl_assert_fingerprint=fingerprint, timeout=30)
            es = Elasticsearch([DB_URL], http_auth=(DB_NAME, DB_PASSWORD),
                               ssl_assert_fingerprint=FINGUREPRINT, timeout=30)
            return es
        except Exception as e:
            print(str(e))
# connection with remote db
def get_elastic_client_test_db():
    if production:
        try:
            fingerprint = ("15:BA:EA:56:47:8A:E0:63:50:25:4B:FE:C2:30:83:29:93:12:05:84:D6:F3:21:39:8F:87:10:B7:FD:AE:EE:56")
            es = Elasticsearch(["https://58.65.202.98:9200"], http_auth=("elastic", "ElasticTest!)@("),
                               ssl_assert_fingerprint=fingerprint, timeout=30)
            print("connection established.....")
            return es
        except Exception as e:
            print(str(e))



