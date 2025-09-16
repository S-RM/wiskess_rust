"""
Polars HostInfo - Host Information reporter based on polars

Author: Gavin Hull
Version: 0.0.1

This parses the files of the Analysis folder of Wiskess and creates a summary of the host info
"""

from datetime import datetime
import polars as pl
import os
import argparse
import re
import glob



def put_timeline(host_info, df, value):
    for _time in host_info.get(value).split(', '):
        data_frame = pl.DataFrame({
            'datetime': _time,
            'timestamp_desc': f'Hostinfo - {value}',
            'message': value
        })
        df = pl.concat([df, data_frame])
    return df



def get_reg_val(find_value, dict_tln):
    if os.path.exists(dict_tln['registry']['file']):
        for file in os.listdir(dict_tln['registry']['file']):
            if re.search(dict_tln['registry']['regex_file'], file):
                try:
                    df = pl.scan_csv(os.path.join(dict_tln['registry']['file'],file))
                    value = df.filter(
                        pl.col("ValueName") == find_value
                        ).select(
                        pl.col("ValueData")
                        ).collect()
                    value = pl.concat(value).unique(maintain_order=True).str.concat(", ").item()
                    return value
                except Exception as e:
                    print(f'Ran into an error when trying to get the value from the registry.')
                    print('Error was:', e) 
    return 'Unknown'


def get_security_retention(channel, art_type, dict_tln):
    if os.path.exists(dict_tln[art_type]['file']):
        # get the timestamp from the earliest event in the Security Channel
        try:
            df = pl.scan_csv(os.path.join(dict_tln[art_type]['file']))
            security_events = df.filter(
                pl.col('Channel') == channel
            ).select(
                dict_tln[art_type]['times']
            ).sort(
                dict_tln[art_type]['times']
            )
            security_retention = f"From: {security_events.first().collect().item()} to: {security_events.last().collect().item()}"
            return security_retention
        except Exception as e:
            print(f'Ran into an error when trying to get the earliest EVTX event from the Security channel.')
            print('Error was:', e)
    return '',''
            

def get_hostname(dict_tln):
    host_reg = get_reg_val("ComputerName", dict_tln)

    # hostname not found in registry
    if os.path.exists(dict_tln['hayabusa']['file']):
        # get the hostname from the last line in the hayabusa output
        print("Getting hostname from hayabusa last line ", dict_tln['hayabusa']['file'])
        try:
            df = pl.scan_csv(os.path.join(dict_tln['hayabusa']['file']))
            host_evt = df.filter(
                (pl.col("Channel") == "Sec") &
                (pl.col("EventID") == 4624)
            ).select(
                pl.col("Computer")
            )
            host_evt = host_evt.tail(1).collect().item().split('.')[0]
        except Exception as e:
            print(f'Ran into an error when trying to get the hostname from hayabusa.')
            print('Error was:', e) 
            host_evt = 'Unknown'
    return host_reg, host_evt



def get_hostinfo(out_filepath, out_filename):
    dict_tln = {
        'registry': {
        'regex_file': r'reg-System\.csv$',
        'file': f'{out_filepath}\\Registry\\',
        'out': f'{out_filepath}\\Timeline\\registry.csv',
        'msg': ['HivePath','Description','Category','ValueName','ValueData','ValueData2','ValueData3','Comment'],
        'times': ['LastWriteTimestamp'],
        'fmt_time': '%F %T%.f'    
        },
        'hayabusa': {
        'file': f'{out_filepath}\\EventLogs\\hayabusa.csv',
        'out': f'{out_filepath}\\Timeline\\hayabusa.csv',
        'msg': ['Computer','Channel','EventID','Level','MitreTactics','MitreTags','OtherTags','RecordID','Details','ExtraFieldInfo','RuleFile','EvtxFile'],
        'times': ['datetime'],    
        'fmt_time': '%FT%T%.f'    
        },
        'event-logs': {
        'file': os.path.join(*[f'{out_filepath}','EventLogs','EvtxECmd-All.csv']),
        'out': os.path.join(*[f'{out_filepath}','Timeline','event-logs.csv']),
        'msg': ['EventId','Level','Provider','Channel','Computer','UserId','MapDescription','UserName','RemoteHost','Payload'],
        'times': ['TimeCreated'],
        'fmt_time': '%F %T%.f'
        },
    }

    host_reg, host_evt = get_hostname(dict_tln)
    
    security_retention = get_security_retention('Security', 'event-logs', dict_tln)
    if security_retention == "":
        security_retention = get_security_retention('Sec', 'hayabusa', dict_tln)
    
    host_info = {
        'Hostname Registry': host_reg,
        'Hostname Event Logs': host_evt,
        'Windows Version (Product Name)': get_reg_val("ProductName", dict_tln),
        'Windows Version (Display Version)': get_reg_val("DisplayVersion", dict_tln),
        'Build Lab': get_reg_val("BuildLab", dict_tln),
        'Timezone': get_reg_val("TimeZoneKeyName", dict_tln),
        'ActiveTimeBias': get_reg_val("ActiveTimeBias", dict_tln),
        'Bias': get_reg_val("Bias", dict_tln),
        'IP Address': get_reg_val("IPAddress", dict_tln),
        'DHCP IP Address': get_reg_val("DhcpIPAddress", dict_tln),
        'DHCP Default Gateway': get_reg_val("DhcpDefaultGateway", dict_tln),
        'DHCP Name Server': get_reg_val("DhcpNameServer", dict_tln),
        'Install Date': get_reg_val("InstallDate", dict_tln),
        'Shutdown Time': get_reg_val("ShutdownTime", dict_tln),
        'Last Logged On User': get_reg_val("LastLoggedOnUser", dict_tln),
        'Security Log Retention': security_retention
    }

    out_file = os.path.join(out_filepath, out_filename)
    with open(out_file, 'w') as file:
        file.write("WISKESS\n----------------\n\nHost Information\n----------------\n\n")
        
    # create empty data frame fror the timeline
    df = pl.DataFrame({})
    
    for i in host_info:
        print(f"{i}: {host_info[i]}")
        with open(out_file, 'a') as file:
            file.write(f"{i}: {host_info[i]}\n")
        # add the host information to a timeline with timestamp of when it was generated
        data_frame = pl.DataFrame({
            'datetime': datetime.today().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'timestamp_desc': f'Hostinfo - All host info. NOTE: `datetime` timestamp is when WISKESS generated the report.',
            'message': f'{i}: {host_info[i]}'
        })
        df = pl.concat([df, data_frame])
    
    df = put_timeline(host_info, df, 'Shutdown Time')
    df = put_timeline(host_info, df, 'Install Date')
    df = df.unique(maintain_order=True)
    output_csv = os.path.join(out_filepath, 'Timeline', out_filename.replace('.txt','.csv'))
    print(f'[ ] Writing host info to CSV as a timeline entry here: {output_csv}')
    df.write_csv(output_csv)
    df.write_ndjson(output_csv.replace('.csv', '.json'))



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out_filepath')
    parser.add_argument('out_file')
    args = parser.parse_args()
    
    get_hostinfo(args.out_filepath, args.out_file)
  


if __name__ == '__main__':
  main()