use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
pub fn valid_process<'a>(wiskers: &'a Vec<Wiskers>, main_args: &config::MainArgs, data_paths: &'a HashMap<String, String>, data_source: &String, out_log: &PathBuf) {
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
        if input_file != "wiskess_none" && input_file != "" {
            let check_outfile = Path::new(&main_args.out_path)
                .join(&wisker.outfolder)
                .join(&wisker.outfile);
            let outfile = format!("{}/{}", &wisker.outfolder, &wisker.outfile);
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
                    analysis_file: outfile,
                    data_source: input_file.replace(data_source,""),
                    lines: file_lines
                };
                contents.push(content);
            }
        }
    }
    let msg = format!(
        "\n{}\n{}{}, {}\n",
        "[ ] Validation checks have found an input data source has not been processed. This is normally due to the output analysis file being shorter than two lines.",
        "[ ] Please check the output of each in the wiskess log: ", 
        out_log.display(),
        "or the output in this terminal.",
    );
    out_table(contents, &out_log, msg);
}

fn out_table(contents: Vec<Summary>, out_log: &Path, msg: String) {
    let mut table = Table::new(&contents);
    table.with(Style::psql());
    table.with(Width::wrap(200));
    table.with(Width::increase(75));
    println!("{}", table.to_string());
    println!("{}", msg);
    file_ops::log_msg(&out_log, table.to_string());
    file_ops::log_msg(&out_log, msg);
}
