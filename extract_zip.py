import os
import zipfile

def extract_zipfile(file_path):
    print("extract zip file called")
    """
    Extracts a zip file and returns the path of the extracted HTML file.

    :param file_path: Path to the zip file.
    :return: Path of the extracted HTML file.
    """

    # extract_path = '/home/muxair/Desktop/suspicious_endpoints/pcaps/'

    extract_path = "/disk0/suspicious-domains-endpoints/code/pcaps/"

    folder_name = 'extracted_pcaps'
    extracted_folder_path = os.path.join(extract_path, folder_name)
    print("extracted_folder_path : ", extracted_folder_path)
    # check if the folder doesn't exist, then create it
    if not os.path.exists(extracted_folder_path):
        os.makedirs(extracted_folder_path)

    try:
        password = get_password(file_path)
        print("password to extract zip: ", password)
        if password != "invalid":
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_folder_path, pwd=password.encode('utf-8'))

            extracted_files = zip_ref.namelist()
            if extracted_files:
                extracted_file_path = os.path.join(extracted_folder_path, extracted_files[0])
                if os.path.exists(extracted_file_path):
                    print(f"Extraction successful for: {file_path}")
    except zipfile.BadZipFile:
        print("Invalid ZIP file or incorrect password.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_password(dir_name):
    try:
        file_path = os.path.basename(dir_name)
        if file_path.__contains__('.'):
            file_name = file_path.split('.')[0].strip()

        # if len(file_name) == 69:        # to extract html zip file
        #     return ''.join([file_name[i] for i in [7, 15, 23, 31, 39, 47, 55, 63]])
        # else:
        #     return "invalid"

        if len(file_name) == 64:               # to extract only zip file (pcap)
            return ''.join([file_name[i] for i in [7, 15, 23, 31, 39, 47, 55, 63]])
        else:
            return "invalid"

    except Exception as e:
        print(f"An error occurred: {e}")
        return "invalid"





