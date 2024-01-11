use std::collections::HashMap;
use crate::configs::config::{Wiskers, self};
use super::file_ops;
use tabled::{Tabled, Table};
use tabled::settings::{Width, Style};

#[derive(Tabled)]
struct Summary<'a> {
    name: &'a str,
    data_source: String,
    analysis_file: String,
    lines: usize,
}

// TODO: Loop through all inputs, on match check output file exists
// Needs the wisker: outfolder, outfile, input
// data_paths is a hashmap of the 'artefact_name : path/to/artefact'
// wiskers is a vector of type Wiskers, which is built from the config file, i.e. config/main_win.yaml
pub fn valid_process<'a>(wiskers: &'a Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &'a HashMap<String, String>, data_source: &String, out_log: &String) {
    let mut contents: Vec<Summary> = Vec::new();
    // let w = wiskers;
    // let mut success = Vec::new();
    for wisker in wiskers {
        // for each function in the wiskers config
        let input_file = match &wisker.valid_path.is_empty() {
            true => data_paths[&wisker.input].clone(),
            false => wisker.valid_path.replace("{root}", data_source)
        };
        // Get input paths that exist in the data source
        if input_file != "wiskess_none" {
            let folder_path = format!("{}/{}", &main_args.out_path, &wisker.outfolder);
            let check_outfile = format!("{}/{}", &folder_path, &wisker.outfile);
            // Check if the outfile exists, file_exists returns false if exists
            let input_not_processed = file_ops::file_exists(
                &check_outfile,
                true
            );
            let mut file_lines = 0;
            if !input_not_processed {
                file_lines = file_ops::line_count(&check_outfile);
            }
            if input_not_processed || file_lines <= 1 {
                // let outfile = check_outfile;
                let content = Summary {
                    name: &wisker.name,
                    data_source: check_outfile,
                    analysis_file: input_file,
                    lines: file_lines
                };
                contents.push(content);
            }
        }
    }
    let msg = format!(
        "{}\n{}\n{}{out_log}, {}\n{}",
        "[!] Please check the logs and config of the above wiskers.",
        "[ ] Validation checks have found an input for these, but no corresponding output file.",
        "[ ] Places you can look are the wiskess log: ", 
        "or the output in this terminal.",
        "[ ] Also please check the output file, as validation checks for it having > 1 line."
    );
    out_table(contents, &out_log, msg);
}

fn out_table(contents: Vec<Summary>, out_log: &String, msg: String) {
    let mut table = Table::new(&contents);
    let mut table_file = Table::new(&contents);
    table.with(Style::psql());
    table_file.with(Style::psql());
    table.with(Width::wrap(200));
    table.with(Width::increase(75));
    println!("{}", table.to_string());
    println!("{}", msg);
    file_ops::log_msg(&out_log, table_file.to_string());
    file_ops::log_msg(&out_log, msg);
}
