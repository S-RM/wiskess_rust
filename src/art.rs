pub mod paths {
    use std::{env, path::Path, collections::HashMap};
    use glob::glob;
    use inquire::Text;
    use crate::{configs::config::{self, Artefacts}, ops::{get_files, file_ops::{self, log_msg}}};

    pub fn check_art(artefacts: Vec<Artefacts>, data_source: &String, silent: bool, main_args: &config::MainArgs) -> HashMap<String, String> {
        let mut art_paths = HashMap::new();
        // TODO: Loop through all artefact paths and check if file/folder exists, if not check alt and legacy path
        for art in artefacts {
            let art_name = format!("{}", art.name);
            let path_str = &art.path.replace(
                "{root}", 
                data_source
            );
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
                    file_ops::log_msg(&main_args.out_log, format!("[-] Path for {} not found at {}", art.name, path_str));
                    if silent {
                        // path not found, set as empty to skip processing
                        art_paths.insert(
                            art.name,
                            "wiskess_none".to_string()
                        );
                    } else {
                        // ask the user for the path
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

    /// check the mounted drive artefact is readable, and if not copy to the 
    /// "out_path/Artefacts" folder. This works on windows-only, as linux has no
    /// issue with permissions of mounted artefacts. It will check if the base
    /// path is a drive letter, and return early if not, as that's typically a collection.
    /// 
    /// Return: the updated datapaths with any copied files and the original paths
    /// 
    /// Args:
    /// * `data_paths` - a hash of the artefact name and filepath of it {name:'pagefile',path:'c:/pagefile.sys'}
    /// * `main_args` - a vector of the main args from main.rs, including the output path
    pub fn check_copy_art(data_paths: HashMap<String, String>, main_args: &config::MainArgs) -> HashMap<String, String> {
        let mut data_paths_clone = data_paths.to_owned();
        let base_path = Path::new(&data_paths_clone["base"]);
        match base_path.parent() {
            Some(_) => {
                println!("[DEBUG] This is likely a collection, not collecting.");
                return data_paths_clone;
            },
            None => (),
        };
        if env::consts::OS == "windows" {
            // set the path where artefacts are copied to
            let dest_path = Path::new(&main_args.out_path).join("Artefacts");
            file_ops::make_folders(&dest_path);
            let dest_path_str = dest_path.clone().into_os_string().into_string().unwrap();
            // loop through all artefacts
            for (name, path) in data_paths.iter() {
                if !check_art_access(&path, &main_args.out_log) {
                    // set the string for the filesystem, i.e. `\\\\.\\d:`
                    let filesystem = format!("\\\\.\\{}", &data_paths["base"].replace("\\",""));
                    // set the base_path to remove the root drive, i.e. `d:\\` from the filename, i.e. `d:\\pagefile.sys`
                    let base_path = format!("{}\\", &data_paths["base"]);
                    let filename = &path.replace(&base_path, "");
                    // make dirs of the filename
                    let dest_dir = Path::new(&dest_path_str).join(filename);
                    let path_path = Path::new(path);
                    if path_path.is_file() {
                        file_ops::make_folders(dest_dir.parent().unwrap());
                    } else {
                        file_ops::make_folders(Path::new(&dest_dir.into_os_string()));
                    }
                    let new_path = match get_files::get_file(&filesystem, &filename, &dest_path_str, path_path.is_file()) {
                        Ok(_) => {
                            let msg = format!("[+] Copy done for file: {path}");
                            log_msg(&main_args.out_log, msg);
                            // set the new path replace and colon `:` with underscore `_` as get_file() does that to data streams
                            let new_path = Path::new(&dest_path).join(filename.replace(":", "_")).to_str().unwrap().to_string();
                            new_path
                        }   
                        Err(e) => {
                            let msg = format!("[!] Unable to copy file: {path}. Error: {}\n", e);
                            log_msg(&main_args.out_log, msg);
                            path.to_owned()
                        }
                    };
                    data_paths_clone.insert(name.to_owned(), new_path);
                }
            }
        }
        data_paths_clone    
    }

    fn check_art_access(filepath: &String, out_log: &String) -> bool {
        match file_ops::check_access(&filepath) {
            Ok(_message) => {
                // println!("{message}");
                true
            }
            Err(e) => {
                log_msg(out_log, format!("[!] Unable to read file: {filepath}, please copy it. Error: {}", e));
                false
            }
        }
    }

    /// Ask the user to type the file path of an artefact, this checks if the path
    /// exists. If it doesn't exist it trusts the user's input anyway.
    /// 
    /// Args:
    /// * art_name - the name of the artefact, i.e. pagefile
    /// * art_paths - the file path to the artefact, i.e. c:/pagefile.sys
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
            Err(inquire::InquireError::OperationCanceled) => (),
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
}
