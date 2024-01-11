use std::collections::HashMap;
use crate::configs::config::{Wiskers, self};
use super::file_ops;

// TODO: Loop through all inputs, on match check output file exists
// Needs the wisker: outfolder, outfile, input
// data_paths is a hashmap of the 'artefact_name : path/to/artefact'
// wiskers is a vector of type Wiskers, which is built from the config file, i.e. config/main_win.yaml
pub fn valid_process(wiskers: &Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &HashMap<String, String>, out_log: &String) {
    // let mut failed = Vec::new();
    // let mut success = Vec::new();
    for wisker in wiskers {
        // for each function in the wiskers config
        let input_file = data_paths[&wisker.input].as_str();
        // Get input paths that exist in the data source
        if input_file != "wiskess_none" {
            let folder_path = format!("{}/{}", &main_args.out_path, &wisker.outfolder);
            let check_outfile = format!("{}/{}", &folder_path, &wisker.outfile);
            // Check if the outfile exists, file_exists returns false if exists
            let input_not_processed = file_ops::file_exists(
                &check_outfile,
                true
            );
            if input_not_processed {
                let msg = format!(
                    r#"[!] Please check the logs and config of wisker: {}
[ ] There was an input file for it here: {}
[ ] There is no output file for the wisker at path: {}"#,
                    &wisker.name,
                    input_file,
                    &check_outfile
                );
                println!("{}", msg);
                file_ops::log_msg(&out_log, msg);

            }
        }
    }
}