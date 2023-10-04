"""
Polars HostInfo - Host Information reporter based on polars

Author: Gavin Hull
Version: 0.0.1

This parses the files of the Analysis folder of Wiskess and creates a summary of the host info
"""

import polars as pl
import os
import argparse
import re



def get_reg_val(find_value, dict_tln):
    if os.path.exists(dict_tln['registry']['file']):
        for file in os.listdir(dict_tln['registry']['file']):
            if re.search(dict_tln['registry']['regex_file'], file):
                try:
                    df = pl.scan_csv(os.path.join(dict_tln['registry']['file'],file))
                    host = df.select(
                        ["ValueName","ValueData"]
                        ).filter(
                        pl.col("ValueName") == find_value
                        ).select(
                        pl.col("ValueData")
                        )
                    host = host.collect()[0].item()
                    return host
                except Exception as e:
                    print(f'Ran into an error when trying to get the hostname from the registry.')
                    print('Error was:', e) 
    return 'Unknown'



def get_hostname(dict_tln):
    host_reg = get_reg_val("ComputerName", dict_tln)
    #   else:
    #     print(f"Unable to get hostname from registry file: {file}")

    # hostname not found in registry
    if os.path.exists(dict_tln['hayabusa']['file']):
        # get the hostname from the last line in the hayabusa output
        print("Getting hostname from hayabusa last line ", dict_tln['hayabusa']['file'])
        try:
            df = pl.scan_csv(os.path.join(dict_tln['hayabusa']['file']))
            host_evt = df.select(
                ["Channel","Computer"]
            ).filter(
                (pl.col("Channel") == "Sec") &
                (pl.col("EventID") == "4624")
            ).select(
                pl.col("Computer")
            )
            host_evt = host_evt.tail(1).collect().item().split('.')[0]
        except Exception as e:
            print(f'Ran into an error when trying to get the hostname from hayabusa.')
            print('Error was:', e) 
            host_evt = 'Unknown'
    return host_reg, host_evt



def get_hostinfo(out_filepath):
    dict_tln = {
        'registry': {
        'regex_file': r'reg-System\.csv$',
        'file': f'{out_filepath}\\Analysis\\Registry\\',
        'out': f'{out_filepath}\\Analysis\\Timeline\\registry.csv',
        'msg': ['HivePath','Description','Category','ValueName','ValueData','ValueData2','ValueData3','Comment'],
        'times': ['LastWriteTimestamp'],
        'fmt_time': '%F %T%.f'    
        },
        'hayabusa': {
        'file': f'{out_filepath}\\Analysis\\EventLogs\\hayabusa.csv',
        'out': f'{out_filepath}\\Analysis\\Timeline\\hayabusa.csv',
        'msg': ['Computer','Channel','EventID','Level','MitreTactics','MitreTags','OtherTags','RecordID','Details','ExtraFieldInfo','RuleFile','EvtxFile'],
        'times': ['datetime'],    
        'fmt_time': '%FT%T%.f'    
        },
        # # TODO: FileExecution
        # # TODO: Network
    }

    host_reg, host_evt = get_hostname(dict_tln)
    host_info = {
        'Hostname Registry': host_reg,
        'Hostname Event Logs': host_evt,
        'Product Name': get_reg_val("ProductName", dict_tln),
        'Build Lab': get_reg_val("BuildLab", dict_tln),
        'Timezone': get_reg_val("TimeZoneKeyName", dict_tln),
        'IP Address': get_reg_val("IPAddress", dict_tln),
        'DHCP IP Address': get_reg_val("DhcpIPAddress", dict_tln),
        'DHCP Default Gateway': get_reg_val("DhcpDefaultGateway", dict_tln),
        'DHCP Name Server': get_reg_val("DhcpNameServer", dict_tln),
        'Install Date': get_reg_val("InstallDate", dict_tln),
        'Shutdown Time': get_reg_val("ShutdownTime", dict_tln),
        'Last Logged On User': get_reg_val("LastLoggedOnUser", dict_tln),
    }

    out_file = os.path.join(f"{out_filepath}/Analysis/Host Information.txt")
    with open(out_file, 'w') as file:
        file.write("WISKESS\n----------------\n\nHost Information\n----------------\n\n")
    for i in host_info:
        print(f"{i}: {host_info[i]}")
        with open(out_file, 'a') as file:
            file.write(f"{i}: {host_info[i]}\n")



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out_filepath')
    args = parser.parse_args()
    
    get_hostinfo(args.out_filepath)
  


if __name__ == '__main__':
  main()