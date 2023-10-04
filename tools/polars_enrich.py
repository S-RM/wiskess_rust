"""
Polars Enrich - Threat intel enricher based on polars

Author: Gavin Hull
Version: 0.0.1

This parses the files of the Analysis folder of Wiskess to extract 
atomic and behavioural indicators for enrichment.
"""

import polars as pl
import os
import argparse
import re
import subprocess


def get_indicator(select_col, type, dict_tln):
    if os.path.exists(dict_tln[type]['file']):
        for file in os.listdir(dict_tln[type]['file']):
            if re.search(dict_tln[type]['regex_file'], file):
                try:
                    df = pl.scan_csv(os.path.join(dict_tln[type]['file'],file))
                    indicator = df.select(
                        pl.col(select_col).alias('indicators').drop_nulls()
                        )
                    indicator = indicator.unique()
                    return indicator
                except Exception as e:
                    print(f'Ran into an error when trying to get the indicator {select_col} from the {type}.')
                    print('Error was:', e) 
    return 'Unknown'



def cleanup(file):
    if os.path.exists(file):
        os.remove(file)
    else:
        print(f'[!] Unable to find file {file}')
        
        

def get_indicators(out_filepath, tool_path):
    dict_tln = {
        'amcache': {
            'regex_file': r'(?:Amcache_UnassociatedFileEntries)\.csv$',
            'file': f'{out_filepath}\\Analysis\\FileExecution\\',
            'out': f'{out_filepath}\\Analysis\\Timeline\\amcache.csv',
            'msg': ['SHA1','FullPath','FileExtension','ProductName'],
            'times': ['FileKeyLastWriteTimestamp','FileIDLastWriteTimestamp'],
            'fmt_time': '%F %T'
            },
        'browser-hist': {
            # TODO: resolve parsing error of none utf-8
            'regex_file': r'BrowsingHistory\.csv$',
            'file': f'{out_filepath}\\Analysis\\Network\\',
            'out': f'{out_filepath}\\Analysis\\Timeline\\browser-hist.csv',
            'msg': ['URL','Title','Visited From','Visit Type','Web Browser','User Profile'],
            'times': ['Visit Time'],
            'fmt_time': '%D %r'
            },
    }

    amhashes = get_indicator('SHA1', 'amcache', dict_tln)
    urls = get_indicator('URL', 'browser-hist', dict_tln)
    indicators = pl.concat([amhashes, urls]).collect()
    
    indicator_file = f'{out_filepath}\\Analysis\\FindingsIOCs\\temp_indicators.list'
    indicators.write_csv(indicator_file, has_header=False)
    
    enrich = f'{tool_path}/enrich.exe'
    config = f'{tool_path}/enrich_config.yaml'
    output_file = f'{out_filepath}\\Analysis\\FindingsIOCs\\enriched_indicators.xlsx'
    subprocess.run([enrich, '-silent', '-o', output_file, '-config', config, '-otx', '-i', indicator_file])

    cleanup(indicator_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out_filepath')
    parser.add_argument('tool_path')
    args = parser.parse_args()
    
    get_indicators(args.out_filepath, args.tool_path)
  


if __name__ == '__main__':
  main()