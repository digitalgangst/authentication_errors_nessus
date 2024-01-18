import os, glob
import xmltodict
import json, re
import pandas as pd
import argparse, zipfile

'''
To do:
1-Create and implement an separate file to store regex,plugins,etc
2-Check for more authentication error plugins n create a regex for each one
'''

# Hours spent on this game
count = 7

def parse_args():
    parser = argparse.ArgumentParser(description='Nessus Auth Error Checker')

    parser.add_argument('--all', action='store_true', help='Process all .nessus files in the specified directory')
    parser.add_argument('--dir', help='Path to directory containing .nessus files')
    parser.add_argument('--recursive', action='store_true', help='Search recursively for .nessus files in subdirectories')
    parser.add_argument('--file', help='Specify .nessus file(s), separated by commas (e.g., file1.nessus,file2.nessus)')
    parser.add_argument('--filename', help='Specify the name for the output zip file')

    return parser.parse_args()

def check_params(output_file_path, excel_output_path):
    with open(output_file_path, 'r') as f:
        data = json.load(f)

        if 'NessusClientData_v2' in data and 'Report' in data['NessusClientData_v2']:
            report = data['NessusClientData_v2']['Report']
            report_name = report['@name']

            if 'ReportHost' in report:

                report_names = []
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
                        report_names.append(report_name)
                        ports.append(int(port))
                        services.append(service)
                        protocols.append(protocol)
                        plugin_ids.append(int(plugin_id))
                        plugin_names.append(plugin_name)
                        plugin_outputs.append(plugin_output)

                # DataFrame
                df = pd.DataFrame({
                    'IP': ips,
                    'Report Name': report_names,
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

def process_directory(directory_path, excel_output_path, recursive=False):
    cumulative_df = pd.DataFrame()

    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            if filename.endswith(".nessus"):
                nessus_file_path = os.path.join(root, filename)
                json_output_path = os.path.splitext(nessus_file_path)[0] + "_output.json"

                try:
                    nessus_data = convert_nessus_to_json(nessus_file_path)

                    with open(json_output_path, 'w', encoding='utf-8') as output_file:
                        json.dump(nessus_data, output_file, indent=2)

                    print(f"Created JSON: {json_output_path}")

                    df = check_params(json_output_path, None)
                    cumulative_df = pd.concat([cumulative_df, df], ignore_index=True)

                except Exception as e:
                    print(f"Error: {nessus_file_path}: {e}")

        if not recursive:
            break

    cumulative_df.to_excel(excel_output_path, index=False)
    print(f"Created Excel file {excel_output_path}")

def check_errors(output_file_path, excel_output_path):
    errors = []

    plugins_to_check = [11149, 26917, 35705, 35706, 10428, 102094, 102095, 117885, 110385, 24786, 110723, 135860, 21745, 104410, 117886, 150799, 50350, 110385, 24786, 110723, 135860, 21745, 104410]
    # 11149 - HTTP login failure (preference): Provides a means for HTTP login info, but it also returns login failures when an error happens.
    # 26917 - Nessus Cannot Access the Windows Registry: This means the target's registry was not available. This is most likely caused by the Remote Registry not set correctly either in the scan policy or on the target.
    # 35705 - SMB Registry : Starting the Registry Service during the scan failed: Indicates failure to start remote registry access
    # 35706 - SMB Registry : Stopping the Registry Service after the scan failed: Indicates failure to start remote registry access
    # 10428  SEM OUTPUT - Microsoft Windows SMB Registry Not Fully Accessible Detection: Tests registry access and sets "SMB/registry_full_access" if successful.
    # 102094 - SSH Commands Require Privilege Escalation: Reports commands that failed due to lack of privilege escalation or due to failed privilege escalation. Commands reported here may not have prevented local checks from running but may have caused the plugin associated with each command to fail to produce the expected output. This causes authentication to report as successful, but with insufficient access.
    # 102095 - Authentication Success - Local Checks Not Available: Reports that local checks were unavailable for the identified device or operating system and includes the report of the plugin that logged the unavailability of local checks.
    # 117885 - Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure: Reports protocols with successful authentication that also had subsequent authentication failures logged for the successful credentials.
    # 110385 - Target Credential Issues by Authentication Protocol - Insufficient Privilege
    # 24786 - Nessus Windows Scan Not Performed with Admin Privileges
    # 110723 - Target Credential Status by Authentication Protocol - No Credentials Provided
    # 135860 - WMI Not Available
    # 21745 - OS Security Patch Assessment Failed (Usualy return in the message regex, but not all. Just for safe.)  
    # 104410 - Target Credential Status by Authentication Protocol - Failure for Provided Credentials
    # 117886 - OS Security Patch Assessment Not Available: Reports that local checks were not enabled for an informational reason and lists informational reason details.
    # 150799 - Target Access Problems by Authentication Protocol - Maximum Privilege Account Used in Scan
    # 50350 - OS Identification Failed

    regex_list = [r"(.*?credential\n.*?checks :)", r"However,   ",
                  r"(.*)but no credentials were provided([\s\S]*)(?:$)", r".*Can't connect.*",
                  r"Nessus was unable([\s\S]*?)(?:\n\s*\n|$\n\n)", r"The following error occurred :\s*\n*\s*(.*?)$"
                  ]

    with open(output_file_path) as f:
        json_data = json.load(f)

        for entry in json_data:
            ip = entry["IP"]
            report_name = entry.get("Report Name", "Unknown Report")
            port = entry["Port"]
            service = entry["Service"]
            protocol = entry["Protocol"]
            plugin_id = entry["Plugin ID"]
            plugin_name = entry["Plugin Name"]
            plugin_output = entry["Output"]

            regex_matches = re.findall(r'Message\s*:\s*([^\n-]+)(?:\\n\\n|$)', plugin_output)

            # Check if plugin_id is in plugins_to_check or there are regex matches
            if plugin_id in plugins_to_check or regex_matches:
                error_entry = {
                    'IP': ip,
                    'Report Name': report_name,
                    'Port': port,
                    'Service': service,
                    'Plugin': plugin_name,
                    'Message': "",  # Initialize the 'Message' field as an empty string
                    'Output': plugin_output
                }

                for result in regex_matches:
                    error_entry['Message'] += result.strip() + " "  # Append each regex match to 'Message'

                # If plugin_id is in plugins_to_check, add separate entries for each regex pattern
                if plugin_id in plugins_to_check:
                    for regex_pattern in regex_list:
                        regex_match = re.findall(regex_pattern, plugin_output)
                        if regex_match:
                            for result in regex_match:
                                if isinstance(result, str):
                                    generic_output = result.strip()
                                else:
                                    generic_output = str(result)
                                error_entry = {
                                    'IP': ip,
                                    'Report Name': report_name,
                                    'Port': port,
                                    'Service': service,
                                    'Plugin': plugin_name,
                                    'Message': generic_output,
                                    'Output': plugin_output
                                }
                                errors.append(error_entry)
                        else:
                            errors.append(error_entry)
                else:
                    errors.append(error_entry)

    # Create a DataFrame for errors
    errors_df = pd.DataFrame(errors)

    # Append errors to a new sheet named 'Errors' in the existing Excel file
    with pd.ExcelWriter(excel_output_path, engine='openpyxl', mode='a') as writer:
        errors_df.to_excel(writer, sheet_name='Errors', index=False, header=True)

def remove_outputs(directory_path='.'):
    padrao = os.path.join(directory_path, '**', '*_output.json')

    arquivos = glob.glob(padrao, recursive=True)

    for arquivo in arquivos:
        try:
            os.remove(arquivo)
            print(f"File removed: {arquivo}")
        except OSError as e:
            print(f"Error for remove file {arquivo}: {e}")

def zip_output_files(excel_output_path, json_output_path, directory_path, filename=None):
    base_name = filename if filename else os.path.basename(os.path.normpath(directory_path))
    zip_file_name = f"{base_name}_output.zip"

    with zipfile.ZipFile(zip_file_name, 'w') as zip_file:
        zip_file.write(excel_output_path, os.path.basename(excel_output_path))
        zip_file.write(json_output_path, os.path.basename(json_output_path))

    print(f"Output files zipped as: {zip_file_name}")

def process_single_file(nessus_file_path, excel_output_path, json_output_path):
    cumulative_df = pd.DataFrame()  # Initialize cumulative_df for each file

    try:
        nessus_data = convert_nessus_to_json(nessus_file_path)

        with open(json_output_path, 'w', encoding='utf-8') as output_file:
            json.dump(nessus_data, output_file, indent=2)

        print(f"Created JSON: {json_output_path}")

        df = check_params(json_output_path, None)
        cumulative_df = pd.concat([cumulative_df, df], ignore_index=True)

    except Exception as e:
        print(f"Error: {nessus_file_path}: {e}")

    cumulative_df.to_excel(excel_output_path, index=False)
    print(f"Created Excel file {excel_output_path}")

    
if __name__ == "__main__":
    args = parse_args()

    directory_path = args.dir if args.dir else '.'
    excel_output_path = "output_combined.xlsx"
    json_output_path = "params.json"

    if args.all:
        process_directory(directory_path, excel_output_path, args.recursive)
    elif args.file:
        file_list = args.file.split(',')
        for file_name in file_list:
            nessus_file_path = os.path.join(directory_path, file_name.strip())
            process_single_file(nessus_file_path, excel_output_path, json_output_path)
    else:
        process_directory(directory_path, excel_output_path, args.recursive)

    # Check if the output file exists before reading it
    if os.path.exists(excel_output_path):
        df_excel = pd.read_excel(excel_output_path)
        df_excel = df_excel.fillna("")

        records = df_excel.to_dict(orient='records')

        with open(json_output_path, 'w') as json_file:
            json.dump(records, json_file, indent=2)

        print(f"JSON Created: {json_output_path}")
        check_errors(json_output_path, excel_output_path)

        zip_output_files(excel_output_path, json_output_path, directory_path, args.filename)
        remove_outputs(directory_path)
    else:
        print(f"Error: Output file '{excel_output_path}' not found.")
