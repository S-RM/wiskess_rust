"""
Polars TLN - Timeline generator based on polars

Author: Gavin Hull
Version: 0.0.0

This parses the json files of the Vector output, which parsed a UAC collection
"""

import fileinput
import polars as pl
from datetime import datetime, timedelta 
import os
from chardet import detect
import argparse
import re

# get file encoding type
def get_encoding_type(file):
    with open(file, 'rb') as f:
        raw_data = f.read()
    return detect(raw_data)['encoding']


def conv_file_to_utf8(src_file):
  trg_file = src_file + '.swp'
  from_codec = get_encoding_type(src_file)
  try:  
      with open(src_file, 'r', encoding=from_codec) as f, open(trg_file, 'w', encoding='utf-8') as e:
          text = f.read()
          e.write(text)
      os.remove(src_file)
      os.rename(trg_file, src_file)
  except UnicodeDecodeError:
      print('Decode Error')
  except UnicodeEncodeError:
      print('Encode Error')

def get_hostname(dict_tln):
  host = ''
  
  if os.path.exists(dict_tln['vector-auth']['file']):
    # get the hostname from the last line in the vector-auth output
    print("Getting hostname from vector-auth last line ", dict_tln['vector-auth']['file'])
    try:
      df = pl.scan_ndjson(os.path.join(dict_tln['vector-auth']['file']))
      host = df.select(
          pl.col("hostname")
      )
      host = host.tail(1).collect().item().split('.')[0]
    except Exception as e:
      print(f'Ran into an error when trying to get the hostname from vector-auth.')
      print('Error was:', e) 
    return host
  return "Unknown"


def filter_tln(df, time_from, time_to):
  filtered_range_df = df.filter(
      pl.col('datetime').is_between(datetime.strptime(time_from, '%Y-%m-%d'), datetime.strptime(time_to, '%Y-%m-%d')),
  )
  return filtered_range_df


def df_time(df, art, file, art_time, art_msg, fmt_time, host):
  # filename = file.split('\\')[-1]
  filename = os.path.basename(file)
  # remove duplicate header names that are used as aliases in the list art_msg
  conflict_name = ['message','timestamp_desc','hostname']
  for name in conflict_name:
    if name in art_msg:
      renamed = f'{name}_{art}'
      df = df.rename({name: renamed})
      # replace name with renamed in the list
      art_msg = list(map(lambda x: x.replace(name, renamed), art_msg))

  art_tln = df.select([
    pl.col(art_time).str.replace(r"(?:Z|\s*\+\d{2}.*)$","").str.to_datetime(format=fmt_time).alias('datetime'),
    pl.lit(f'{art} - {filename}: {art_time}').alias('timestamp_desc'),
    pl.concat_str(pl.col(art_msg).fill_null(pl.lit(""),), separator="; ").alias('message'),
    pl.col(art_msg),
    pl.lit(f'{host}').alias('hostname')
    ])
  return art_tln


def get_art_tln(df, art, file, dict_tln, time_from, time_to, host):
  # create empty dataframe for each artefact timeline
  art_tln = pl.DataFrame({})

  for art_time in dict_tln[art]['times']:
    try:
      if(art_time in df):
        # for each time field in the timeline dictionary, get the data and filter based on time_from and time_to
        df_t = df_time(df, art, file, art_time, dict_tln[art]['msg'], dict_tln[art]['fmt_time'], host)
        df_t = filter_tln(df_t, time_from, time_to)
        # Add the parts of the different timelines together
        art_tln = pl.concat([art_tln, df_t.collect()], how='vertical')
    except Exception as e:
      print(f'Possibly no time column called {art_time}')
      print('Error was:', e)

  return art_tln


def get_all_tln(dict_tln, time_from, time_to, host):
  # create empty dataframe for all the artefact timelines
  all_tln = pl.DataFrame({})
  for art in dict_tln:
    # for each file in dict_tln[art]['file'], which can have asterisk
    files = []
    if os.path.isdir(dict_tln[art]['file']):
      for file in os.listdir(dict_tln[art]['file']):
        if re.search(dict_tln[art]['regex_file'], file):
          files.append(os.path.join(dict_tln[art]['file'], file))
    else:
      files.append(dict_tln[art]['file'])

    # create empty dataframe for each artefact timeline
    files_tln = pl.DataFrame({})
    for file in files:
      try:
        if os.path.exists(file):
          print(file)
          try:
            if re.search(r'regripper', file):
              # remove lines that aren't timestamped at start
              for line in fileinput.input(file, inplace = True):
                if re.search(r'^\d{9,11}\|', line):
                  print(line, end='')
              df = pl.scan_csv(file, separator='|', encoding='utf8-lossy', truncate_ragged_lines=True, new_columns=['time','source','system','user','description'])
            elif re.search(r'psv$', file):
              conv_file_to_utf8(file)
              df = pl.scan_csv(file, separator='|')
            elif re.search(r'json(?:l|)|log$', file):
              df = pl.scan_ndjson(file)
            else:
              df = pl.scan_csv(file, encoding='utf8-lossy', infer_schema_length=10000, null_values='-')
          except:
            df = pl.scan_csv(file, ignore_errors=True)
          file_tln = get_art_tln(df, art, file, dict_tln, time_from, time_to, host)
          if(file_tln.width > 0):
            files_tln = pl.concat([files_tln, file_tln], how='vertical')
        else:
          print(f'Not found {file}')
      except Exception as e:
        print(f'Some error occured for {file}.')
        print('Error was:', e)

    if len(files_tln) > 0:
      # Sort the whole timeline by datetime
      files_tln = files_tln.sort('datetime')
      files_tln.write_csv(dict_tln[art]['out'])
      json_outfile = f'{os.path.splitext(dict_tln[art]["out"])[0]}.json'
      files_tln.write_ndjson(json_outfile)

      # Add the files timeline to the all dataframe
      # all_tln = pl.concat([all_tln, files_tln], how='diagonal')

  # return all_tln


def csv_to_tln(out_filepath, time_from, time_to):
  # dict_tln needs the file, out, msg, times and fmt_time. If the file is a dir, the regex_file is needed to match the file name
  dict_tln = {
    'vector-auth': {
      'file': os.path.join(*[f'{out_filepath}','vector-auth.log']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','vector-auth.csv']),
      'msg': ['message','appname','file','procid','source_type','hostname'],
      'times': ['timestamp'],
      'fmt_time': '%FT%T'
    },
    'vector-bodyfile': {
      'file': os.path.join(*[f'{out_filepath}','vector-bodyfile.log']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','vector-bodyfile.csv']),
      'msg': ['filename','permissions','size','message','file','source_type'],
      'times': ['accessed','born','changed','modified'],
      'fmt_time': '%FT%T'
    },
    'vector-syslog': {
      'file': os.path.join(*[f'{out_filepath}','vector-syslog.log']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','vector-syslog.csv']),
      'msg': ['appname','file','host','hostname','message','source_type'],
      'times': ['timestamp'],
      'fmt_time': '%FT%T'
    },
    'vector-nginx': {
      'file': os.path.join(*[f'{out_filepath}','vector-nginx.log']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','vector-nginx.csv']),
      'msg': ['agent','client','file','host','message','referer','request','size','file'],
      'times': ['timestamp'],
      'fmt_time': '%FT%T'
    },
    # 'hayabusa': {
    #   'file': os.path.join(*[f'{out_filepath}','EventLogs','hayabusa.csv']),
    #   'out': os.path.join(*[f'{out_filepath}','Timeline','hayabusa.csv']),
    #   'msg': ['Computer','Channel','EventID','Level','MitreTactics','MitreTags','OtherTags','RecordID','Details','ExtraFieldInfo','RuleFile','EvtxFile'],
    #   'times': ['datetime'],
    #   'fmt_time': '%FT%T%.f'
    # },
  }

  host = get_hostname(dict_tln)
  print(f'Hostname: {host}')

  all_tln = get_all_tln(dict_tln, time_from, time_to, host)
  # put_all_tln(dict_tln)
  # Sort the all timeline by datetime col
  # if all_tln.width > 0:
  #   all_tln = all_tln.sort('datetime')
  #   all_tln.write_csv(f'{out_filepath}\\Timeline\\all.csv')
  #   all_tln.write_ndjson(f'{out_filepath}\\Timeline\\all.json')
  # else:
  #   print('[!] Nothing found in the time range')


def main():
  print('wiskess_timeliner')
  parser = argparse.ArgumentParser()
  parser.add_argument('out_filepath')
  parser.add_argument('time_from')
  parser.add_argument('time_to')
  args = parser.parse_args()

  csv_to_tln(args.out_filepath, args.time_from, args.time_to)

if __name__ == '__main__':
  main()
