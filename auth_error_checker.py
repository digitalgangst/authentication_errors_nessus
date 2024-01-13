import os, glob
import xmltodict
import json, re
import pandas as pd

'''
To do:
1-Create and implement an separate file to store regex,plugins,etc
2-Add "Report Name" entry in excel file/column
3-Add recursive search for .nessus files in directories
4-Add args (?)
5-Check for more authentication error plugins n create a regex for each one
'''

# Hours spent on this game
count = 5

def check_params(output_file_path, excel_output_path):
    with open(output_file_path, 'r') as f:
        data = json.load(f)

        if 'NessusClientData_v2' in data and 'Report' in data['NessusClientData_v2']:
            report = data['NessusClientData_v2']['Report']

            if 'ReportHost' in report:

                ips = []
                ports = []
                services = []
                protocols = []
                plugin_ids = []
                plugin_names = []
                plugin_outputs = []

                # Get hosts
                for host in report['ReportHost']:
                    name = host['@name']
                    for item in host['ReportItem']:
                        plugin_id = item.get('@pluginID')
                        plugin_output = item.get('plugin_output')
                        plugin_name = item.get('@pluginName')
                        port = item.get('@port')
                        service = item.get('@svc_name')
                        protocol = item.get('@protocol')

                        # Append data to list
                        ips.append(name)
                        ports.append(int(port))
                        services.append(service)
                        protocols.append(protocol)
                        plugin_ids.append(int(plugin_id))
                        plugin_names.append(plugin_name)
                        plugin_outputs.append(plugin_output)

                # DataFrame
                df = pd.DataFrame({
                    'IP': ips,
                    'Port': ports,
                    'Service': services,
                    'Protocol': protocols,
                    'Plugin ID': plugin_ids,
                    'Plugin Name': plugin_names,
                    'Output': plugin_outputs
                })

                return df

def convert_nessus_to_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as nessus_file:
        nessus_data = nessus_file.read()

    nessus_dict = xmltodict.parse(nessus_data)

    return nessus_dict

def process_directory(directory_path, excel_output_path):
    cumulative_df = pd.DataFrame()

    for filename in os.listdir(directory_path):
        if filename.endswith(".nessus"):
            nessus_file_path = os.path.join(directory_path, filename)
            json_output_path = os.path.splitext(nessus_file_path)[0] + "_output.json"

            try:
                nessus_data = convert_nessus_to_json(nessus_file_path)

                with open(json_output_path, 'w', encoding='utf-8') as output_file:
                    json.dump(nessus_data, output_file, indent=2)

                print(f"Created JSON: {json_output_path}")

                df = check_params(json_output_path, None)
                cumulative_df = pd.concat([cumulative_df, df], ignore_index=True)

            except Exception as e:
                print(f"Error: {filename}: {e}")

    cumulative_df.to_excel(excel_output_path, index=False)
    print(f"Created Excel file {excel_output_path}")

def check_errors(output_file_path, excel_output_path):
    errors = []

    plugins_to_check = [110385, 24786, 110723, 135860, 21745]

    # 110385 - Target Credential Issues by Authentication Protocol - Insufficient Privilege
    # 24786 - Nessus Windows Scan Not Performed with Admin Privileges
    # 110723 - Target Credential Status by Authentication Protocol - No Credentials Provided
    # 135860 - WMI Not Available
    # 21745 - OS Security Patch Assessment Failed (Usualy return in the message regex, but not all. Just for safe.)

    # Regex for each plugin, if needed
    regex_list = [r"(.*?credential\n.*?checks :)", r"However,([\s\S]*?)(?:\n\s*\n|$\n\n)",
                  r"(.*)but no credentials were provided([\s\S]*)(?:$)", r".*Can't connect.*"] 

    with open(output_file_path) as f:
        json_data = json.load(f)

        for entry in json_data:
            ip = entry["IP"]
            port = entry["Port"]
            service = entry["Service"]
            protocol = entry["Protocol"]
            plugin_id = entry["Plugin ID"]
            plugin_name = entry["Plugin Name"]
            plugin_output = entry["Output"]

            regex = re.findall(r'Message\s*:\s*([^\n-]+)(?:\\n\\n|$)', plugin_output)
            # Outputs with 'Message' field usually are errors
            
            # Check if plugin_id is in plugins_to_check or matches the regex condition
            if plugin_id in plugins_to_check or regex:
                for result in regex:
                    error_entry = {
                        'IP': ip,
                        'Port': port,
                        'Service': service,
                        'Plugin': plugin_name,
                        'Message': result.strip(),
                        'Output': plugin_output
                    }
                    errors.append(error_entry)

                # If plugin_id is in plugins_to_check, add a separate entry
                if plugin_id in plugins_to_check:
                    for regex_pattern in regex_list:
                        regex_matches = re.findall(regex_pattern, plugin_output)
                        for result in regex_matches:
                            if isinstance(result, str):
                                generic_output = result.strip()
                            else:
                                generic_output = str(result)  # Convert to string if not yet
                            error_entry = {
                                'IP': ip,
                                'Port': port,
                                'Service': service,
                                'Plugin': plugin_name,
                                'Message': generic_output,
                                'Output': plugin_output
                            }
                            errors.append(error_entry)

    # Create a DataFrame for errors
    errors_df = pd.DataFrame(errors)

    # Append errors to a new sheet named 'Errors' in the existing Excel file
    with pd.ExcelWriter(excel_output_path, engine='openpyxl', mode='a') as writer:
        errors_df.to_excel(writer, sheet_name='Errors', index=False, header=True)

    # Assuming this function is defined somewhere
    remove_outputs()

def remove_outputs(): # Remove generated json outputs :)
    padrao = os.path.join('.', '*_output.json')

    arquivos = glob.glob(padrao)

    for arquivo in arquivos:
        try:
            os.remove(arquivo)
            print(f"Arquivo removido: {arquivo}")
        except OSError as e:
            print(f"Erro ao remover o arquivo {arquivo}: {e}")
    
if __name__ == "__main__":
    directory_path = '.'
    excel_output_path = "output_combined.xlsx"
    json_output_path = "params.json"

    process_directory(directory_path, excel_output_path)

    df_excel = pd.read_excel(excel_output_path)
    df_excel = df_excel.fillna("")

    records = df_excel.to_dict(orient='records')

    with open(json_output_path, 'w') as json_file:
        json.dump(records, json_file, indent=2)

    print(f"JSON Created: {json_output_path}")
    check_errors(json_output_path, excel_output_path)