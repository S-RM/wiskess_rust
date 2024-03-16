pub mod paths {
    use std::{path::Path, collections::HashMap};
    use glob::glob;
    use inquire::Text;
    use crate::{configs::config::Artefacts, ops::file_ops::{self, log_msg}};

    pub fn check_art(artefacts: Vec<Artefacts>, data_source: &String, silent: bool, out_log: &String) -> HashMap<String, String> {
        let mut art_paths = HashMap::new();
        // TODO: Loop through all artefact paths and check if file/folder exists, if not check alt and legacy path
        for art in artefacts {
            let path_str = &art.path.replace(
                "{root}", 
                data_source
            );
            let art_name = format!("{}", art.name);
            // resolve the path_str into a path, and add it to art_path hash
            get_path(path_str, &mut art_paths, &art_name);
            if art_paths.get(&art.name).is_none() {
                // TODO: check urlencoded filename
                get_enc_path(path_str, &mut art_paths, &art_name);
                if art.legacy != "" {
                    // check legacy path
                    let path_str_leg = &art.legacy.replace(
                        "{root}", 
                        data_source
                    );
                    get_path(&path_str_leg, &mut art_paths, &art_name);
                }
                if art_paths.get(&art.name).is_none() && art.name != "none" {
                    file_ops::log_msg(&out_log, format!("[-] Path for {} not found at {}", art.name, path_str));
                    if silent {
                        // path not found, set as empty to skip processing
                        art_paths.insert(
                            art.name,
                            "wiskess_none".to_string()
                        );
                    } else {
                        // as the user for the path
                        get_users_path(&art_name, &mut art_paths);
                    }
                } else if art.name == "none" {
                    // if art name has been given none in the config, ignore and add
                    art_paths.insert(
                        art.name,
                        art.path.to_string()
                    );
                }
            }
        }
        // Return a hashmap of artefact paths
        art_paths
    }

    fn get_enc_path(path_str: &String, art_paths: &mut HashMap<String, String>, art_name: &String) {
        let path = Path::new(path_str);
        let filename = path.file_name();
        if filename != None {
            let parent = path.parent().unwrap();
            let filename_str = filename.unwrap().to_str().unwrap().replace(":","%3A");
            let enc_path = format!(
                "{}/{}", 
                parent.to_str().unwrap(), 
                filename_str);
            // get the path that has url encoding
            get_path(&enc_path, art_paths, art_name);
        }
    }

    pub fn check_art_access(filepath: &String, out_log: &String) -> bool {
        match file_ops::check_access(&filepath) {
            Ok(message) => {
                println!("{message}");
                true
            }
            Err(e) => {
                log_msg(out_log, format!("[!] Unable to read file: {filepath}, please copy it. Error: {}\n", e));
                false
            }
        }
    }


    fn get_users_path(art_name: &String, art_paths: &mut HashMap<String, String>) {
        let msg = format!("What is the file path of {}?", &art_name);
        let path_ask = Text::new(&msg).prompt();
        match path_ask {
            Ok(path_ask) => {
                get_path(&path_ask, art_paths, &art_name);
                if art_paths.get(art_name).is_none() {
                    // user's path not found, adding to hash anyway
                    art_paths.insert(
                        art_name.to_string(),
                        path_ask
                    );
                }
            },
            Err(_) => println!("An error occured when asking you for the path."),
        }
    }

    fn get_path(path_str: &String, art_paths: &mut HashMap<String, String>, art_name: &String) {
        let path_arg = Path::new(path_str);
        if path_arg.exists() {
            // add path to hash
            art_paths.insert(
                art_name.to_string(),
                path_arg.display().to_string()
            );
        } else {
            if is_glob_path(path_str) {
                // add path to hash
                art_paths.insert(
                    art_name.to_string(),
                    path_arg.display().to_string()
                );
            }
        }
    }

    fn is_glob_path(path_str: &String) -> bool {
        // Get path from glob based path  
        for entry in glob(path_str).expect("Unable to read glob pattern") {
            match entry {
                Ok(_) => {
                    return true;
                },
                Err(e) => {
                    println!("{:?}", e);
                    return false;
                }
            }
        }
        return false
    }

    pub fn get_glob_path(path_str: &String) -> String {
        // Get path from glob based path  
        for entry in glob(path_str).expect("Unable to read glob pattern") {
            match entry {
                Ok(_) => {
                    return entry.unwrap().into_os_string().into_string().unwrap();
                },
                Err(e) => {
                    println!("{:?}", e);
                    return "".to_string();
                }
            }
        }
        return "".to_string()
    }
}
