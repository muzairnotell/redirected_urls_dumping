from db_connection import get_elastic_client, get_elastic_client_test_db
import hashlib
import traceback

class CRUD():
    def __init__(self):
        self.suspicious_index = 'suspicious_domains'
        self.pishing_index = 'phishing_intelligence_v2'
        self.ss_index = 'screenshot_primary_v2'

        self.es = get_elastic_client()
        # self.es = get_elastic_client_test_db()

            # print(f"Index '{index_name}' created successfully.")
    
    def get_data_by_frequency(self, frequency : int):
        response = {}
        try:
            search_query = {
                
                "query": {
                    "range": {
                    "frequency": {
                        "gte": frequency
                    }
                    }
                }
            }

            response = self.es.search(index=self.suspicious_index, body=search_query)
            # response = test_db.search(index=self.suspicious_index, body=search_query)
            response = response['hits']['hits']

        except Exception as e:
            print(f"get_data_by_frequency Exception : {e}")

        finally:
            return response
    
    def get_data(self, id: str):
        """
        This method is returning document against id.
        """
        try:

            response = self.es.get(index=self.pishing_index, id=id)
            return response

        except Exception as e:
            print(f"Error in get_vendor_name : {e}")
            return None

    def get_score(self, id):
        """Get score from db phishing_intelligence_v2 of articats."""
        try:
            query = {"query": {
            "ids": {
            "values": [id]
                }

            }}
            response = self.es.search(index=self.pishing_index, body=query)  # here we removed size parameter
            # pprint(response['hits']['hits'])

            score = response['hits']['hits'][0]['_source']['score']  if response['hits']['hits'] != [] else None
            # print(score)
            return score
        
        except Exception as e:
            print("Error in get_score : ",e)
            return None


    def get_score_and_date(self, id: str) -> tuple:
        """Get score and updated date from the Elasticsearch database phishing_intelligence_v2 of artifacts."""
        try:
            query = {
                "query": {
                    "ids": {
                        "values": [id]
                    }
                }
            }
            response = self.es.search(index=self.pishing_index, body=query)  # size parameter removed

            if response['hits']['hits']:
                source = response['hits']['hits'][0]['_source']
                score = source.get('score')
                created_date = source.get('created_at')
            else:
                score = None
                created_date = None

            return score, created_date

        except Exception as e:
            print("Error in get_score_and_date:", traceback.format_exc())
            return None, None

    def search_domain(self,  domain: str):
        """
        This script will search domain in suspicious index and will return it if exist.
        """
        search_result = None
        try:
            domain_id = hashlib.sha256(domain.encode('utf-8')).hexdigest()
            search_result = self.es.get(index=self.suspicious_index, id=domain_id)
            # search_result["_source"]['status'] = True
            # return search_result["_source"]
        
        except Exception as e:
            print(f"Error in search_domain : {e}")
            # response = {"response" : f"domamin {domain} Not found.",
                # "status" : False}
        finally:
            return search_result['_source']
        
    
    def search_pcap(self, pcap_id: str):
        """
        This script will search pcap id in index and will return matching results.
        """

        try:
            search_body = {
                'query': {
                    'terms': {
                        'pcap_path.keyword': [pcap_id]
                    }
                }
            }

            
            response = self.es.search(index=self.suspicious_index, body=search_body)
            response = [hit["_source"] for hit in response['hits']['hits']]

            return response
            
        except Exception as e:
            print(f"Error in search_pcap function : {e}")
            return {"response" : f"pcap id {pcap_id} Not found."}

    def update_frequencies(self, domain : str, flag : str):

        try:
            domain_id = hashlib.sha256(domain.encode('utf-8')).hexdigest()
            result = self.es.get(index=self.index_name, id=domain_id)
            if result['_source']:
                print(result['_source'])
                print(result['_source']['frequency'])
                print(result['_source']['benign_frequency'])
                mal_frequency = result['_source'].get('frequency',0)
                begning_frequency = result['_source'].get('benign_frequency',0)
                if flag.lower() == "fp":
                    updated_query = {
                        "doc": {
                        "frequency" : max(mal_frequency-1,0),
                        "benign_frequency" : begning_frequency+1
                      }
                    }
                elif flag.lower() == 'fn':
                    
                    updated_query = {
                        "doc": {
                        "frequency" : mal_frequency+1,
                        "benign_frequency" : max(begning_frequency-1,0)
                        }
                    }
                self.es.update(index=self.suspicious_index, id=domain_id, body=updated_query)
                print(updated_query)
        except Exception as e:
            print(f"Exception as e : {e}")



