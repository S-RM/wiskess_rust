"""
Polars TLN - Timeline generator based on polars

Author: Gavin Hull
Version: 0.1.0

This parses the files of the Analysis folder of Wiskess and creates CSV and json files 
in a timeline that is between the start and end time specified on the CLI
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
  if os.path.exists(dict_tln['registry']['file']):
    for file in os.listdir(dict_tln['registry']['file']):
      if re.search(dict_tln['registry']['regex_file'], file):
        try:
          df = pl.scan_csv(os.path.join(dict_tln['registry']['file'],file))
          host = df.filter(
              pl.col("ValueName") == "ComputerName"
            ).select(
              pl.col("ValueData")
            )
          host = host.collect()[0].item()
          return host
        except Exception as e:
          print('Ran into an error when trying to get the hostname from the registry.')
          print('Error was:', e)
      else:
        print(f"Unable to get hostname from registry file: {file}")
  # hostname not found in registry
  if os.path.exists(dict_tln['hayabusa']['file']):
    # get the hostname from the last line in the hayabusa output
    print("Getting hostname from hayabusa last line ", dict_tln['hayabusa']['file'])
    try:
      df = pl.scan_csv(os.path.join(dict_tln['hayabusa']['file']))
      host = df.filter(
          (pl.col("Channel") == "Sec") &
          (pl.col("EventID") == 4624)
      ).select(
          pl.col("Computer")
      )
      host = host.tail(1).collect().item().split('.')[0]
    except Exception as e:
      print(f'Ran into an error when trying to get the hostname from hayabusa.')
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
            elif re.search(r'json(?:l|)$', file):
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
    'registry': {
      'regex_file': r'reg-(?:System|User)\.csv$',
      'file': os.path.join(*[f'{out_filepath}','Registry']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','registry.csv']),
      'msg': ['HivePath','Description','Category','ValueName','ValueData','ValueData2','ValueData3','Comment'],
      'times': ['LastWriteTimestamp'],
      'fmt_time': '%F %T%.f'
    },
    'hayabusa': {
      'file': os.path.join(*[f'{out_filepath}','EventLogs','hayabusa.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','hayabusa.csv']),
      'msg': ['Computer','Channel','EventID','Level','MitreTactics','MitreTags','OtherTags','RecordID','Details','ExtraFieldInfo','RuleFile','EvtxFile'],
      'times': ['datetime'],
      'fmt_time': '%FT%T%.f'
    },
    'amcache': {
      'regex_file': r'(?:Amcache_UnassociatedFileEntries)\.csv$',
      'file': os.path.join(*[f'{out_filepath}','FileExecution']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','amcache.csv']),
      'msg': ['SHA1','FullPath','FileExtension','ProductName'],
      'times': ['FileKeyLastWriteTimestamp','FileIDLastWriteTimestamp'],
      'fmt_time': '%F %T'
    },
    'prefetch': {
      'file': os.path.join(*[f'{out_filepath}','FileExecution','prefetch_Timeline.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','prefetch.csv']),
      'msg': ['ExecutableName'],
      'times': ['RunTime'],
      'fmt_time': '%F %T%.f'
    },
    'appcompatcache': {
      'file': os.path.join(*[f'{out_filepath}','FileExecution','appcompatcache.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','appcompatcache.csv']),
      'msg': ['ControlSet','CacheEntryPosition','Path','Executed','Duplicate','SourceFile'],
      'times': ['LastModifiedTimeUTC'],
      'fmt_time': '%F %T'
    },
    'sccm_execution': {
      'file': os.path.join(*[f'{out_filepath}','FileExecution','SCCM_RecentlyUsedApplication.psv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','sccm_recentlyused.csv']),
      'msg': ['FolderPath','ExplorerFileName','LastUserName','LaunchCount','FileDescription','CompanyName','ProductName'],
      'times': ['LastUsedTime'],
      'fmt_time': '%F %T'
    },
    'network_sum': {
      'regex_file': r'(?:SumECmd_DETAIL_ClientsDetailed_Output)\.csv$',
      'file': os.path.join(*[f'{out_filepath}','Network']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','network.csv']),
      'msg': ['Count','DayNumber','RoleGuid','RoleDescription','AuthenticatedUserName','TotalAccesses','IpAddress','ClientName','TenantId','SourceFile'],
      'times': ['InsertDate','LastAccess'],
      'fmt_time': '%F %T'
    },
    'browser-hist_uk': {
      # for browsing history processed on machines with timestamps in UK format
      'file': os.path.join(*[f'{out_filepath}','Network','BrowsingHistory.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','browser-hist.csv']),
      'msg': ['URL','Title','Visited From','Visit Type','Web Browser','User Profile'],
      'times': ['Visit Time'],
      'fmt_time': '%d/%m/%Y %T'
    },
    'browser-hist_us': { 
      # for browsing history processed on machines with timestamps in US format
      'file': os.path.join(*[f'{out_filepath}','Network','BrowsingHistory.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','browser-hist.csv']),
      'msg': ['URL','Title','Visited From','Visit Type','Web Browser','User Profile'],
      'times': ['Visit Time'],
      'fmt_time': '%m/%d/%Y %r'
    },
    'shellbags': {
      'regex_file': r'(?:UsrClass|NTUSER)\.csv$',
      'file': os.path.join(*[f'{out_filepath}','UserActivity']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','shellbags.csv']),
      'msg': ['AbsolutePath','ShellType','Value'],
      'times': ['CreatedOn','ModifiedOn','AccessedOn','LastWriteTime','FirstInteracted','LastInteracted'],
      'fmt_time': '%F %T'
    },
    'jump-lists': {
      'regex_file': r'(?:AutomaticDestinations|CustomDestinations)\.csv$',
      'file': os.path.join(*[f'{out_filepath}','UserActivity']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','jump-lists.csv']),
      'msg': ['SourceFile','AppIdDescription','MachineID','LocalPath','CommonPath','TargetIDAbsolutePath','FileSize','Arguments'],
      'times': ['SourceCreated','SourceModified','SourceAccessed','TargetCreated','TargetModified','TargetAccessed','TrackerCreatedOn'],
      'fmt_time': '%F %T'
    },
    'lnk-files': {
      'file': os.path.join(*[f'{out_filepath}','FileSystem','lnk-files.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','lnk-files.csv']),
      'msg': ['SourceFile','FileSize','RelativePath','WorkingDirectory','LocalPath','NetworkPath','CommonPath','Arguments','MachineID'],
      'times': ['SourceCreated','SourceModified','SourceAccessed','TargetCreated','TargetModified','TargetAccessed','TrackerCreatedOn'],
      'fmt_time': '%F %T'
    },
    'recycle-bin': {
      'regex_file': r'RBCmd_Output\.csv$',
      'file': os.path.join(*[f'{out_filepath}','FileSystem']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','recycle-bin.csv']),
      'msg': ['FileName','FileSize'],
      'times': ['DeletedOn'],
      'fmt_time': '%F %T'
    },
    'mft':{
      'file': os.path.join(*[f'{out_filepath}','FileSystem','MFTECmd.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','MFTECmd.csv']),
      'msg':['ParentPath','FileName','Extension','FileSize'],
      'times':['Created0x10','Created0x30','LastModified0x10','LastModified0x30','LastRecordChange0x10','LastRecordChange0x30','LastAccess0x10','LastAccess0x30'],
      'fmt_time': '%F %T%.f'
    },
    'event-logs': {
      'file': os.path.join(*[f'{out_filepath}','EventLogs','EvtxECmd-All.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','event-logs.csv']),
      'msg': ['EventId','Level','Provider','Channel','Computer','UserId','MapDescription','UserName','RemoteHost','Payload'],
      'times': ['TimeCreated'],
      'fmt_time': '%F %T%.f'
    },
    'usnjrnl-j':{
      'file': os.path.join(*[f'{out_filepath}','FileSystem','usnjrnl-j-file.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','usnjrnl-j-file.csv']),
      'msg': ['Name','Extension','EntryNumber','ParentEntryNumber','ParentPath','UpdateReasons','FileAttributes'],
      'times': ['UpdateTimestamp'],
      'fmt_time': '%F %T%.f'
    },
    'rusty_usnjrnl': {
      'file': os.path.join(*[f'{out_filepath}','FileSystem','usnjrnl_j.json']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','usnjrnl_j_rusty.csv']),
      'msg': ['file_name','full_name','file_name_length','reason','file_attributes'],
      'times': ['timestamp'],
      'fmt_time': '%FT%T%.f'
    },
    'mft_dump': {
      'file': os.path.join(*[f'{out_filepath}','FileSystem','mft.csv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','mft_dump.csv']),
      'msg': ['FullPath','TotalEntrySize','FileSize','StandardInfoFlags','FileNameFlags','IsADirectory','IsDeleted','HasAlternateDataStreams'],
      'times': ['StandardInfoLastModified','StandardInfoLastAccess','StandardInfoCreated','FileNameLastModified','FileNameLastAccess','FileNameCreated'],
      'fmt_time': '%FT%T%.f'
    },
    'hindsight': {
      'file': os.path.join(*[f'{out_filepath}','Network','hindsight.jsonl']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','hindsight.csv']),
      'msg': ['url','timestamp_desc','message','value','interpretation','data_type','source_long','profile'],
      'times': ['datetime'],
      'fmt_time': '%FT%T%.f'
    },
    'regripper_exe': {
      'file': os.path.join(*[f'{out_filepath}','FileExecution','regripper_amcache.psv']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','regripper_amcache.csv']),
      'msg': ['source','system','user','description'],
      'times': ['time'],
      'fmt_time': '%s'
    },
    'regripper_reg': {
      'regex_file': r'^regripper.*\.psv$',
      'file': os.path.join(*[f'{out_filepath}','Registry','regripper_tln']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','regripper.csv']),
      'msg': ['source','system','user','description'],
      'times': ['time'],
      'fmt_time': '%s'
    },
    'srum_net_usages': {
      'regex_file': r'_SrumECmd_NetworkUsages_Output\.csv$',
      'file': os.path.join(*[f'{out_filepath}','Network']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','srum_net_usages.csv']),
      'msg': ['ExeInfo','ExeInfoDescription','ExeTimestamp','SidType','Sid','UserName','UserId','AppId','BytesReceived','BytesSent','InterfaceLuid','InterfaceType','L2ProfileFlags','L2ProfileId','ProfileName'],
      'times': ['Timestamp'],
      'fmt_time': '%F %X'
    },
    'srum_app_resusages': {
      'regex_file': r'_SrumECmd_AppResourceUseInfo_Output\.csv$',
      'file': os.path.join(*[f'{out_filepath}','Network']),
      'out': os.path.join(*[f'{out_filepath}','Timeline','srum_app_resusages.csv']),
      'msg': ['ExeInfo','ExeInfoDescription','ExeTimestamp','SidType','Sid','UserName','UserId','AppId','BackgroundBytesRead','BackgroundBytesWritten','BackgroundContextSwitches','BackgroundCycleTime','BackgroundNumberOfFlushes','BackgroundNumReadOperations','BackgroundNumWriteOperations','FaceTime','ForegroundBytesRead','ForegroundBytesWritten','ForegroundContextSwitches','ForegroundCycleTime','ForegroundNumberOfFlushes','ForegroundNumReadOperations','ForegroundNumWriteOperations'],
      'times': ['Timestamp'],
      'fmt_time': '%F %X'
    }
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
