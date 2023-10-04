pub mod paths {
    use std::{path::Path, collections::HashMap};
    use glob::glob;
    use inquire::Text;
    use crate::{configs::config::Artefacts};
    use urlencoding::encode;

    pub fn check_art(artefacts: Vec<Artefacts>, data_source: &String, silent: bool) -> HashMap<String, String> {
        let mut art_paths = HashMap::new();
        // TODO: Loop through all artefact paths and check if file/folder exists, if not check alt and legacy path
        for art in artefacts {
            let path_str = &art.path.replace(
                "{root}", 
                data_source
            );
            let art_name = format!("{}", art.name);
            get_path(path_str, &mut art_paths, &art_name);
            if art_paths.get(&art.name).is_none() {
                // TODO: check urlencoded filename
                let path = Path::new(path_str);
                let filename = path.file_name();
                if filename != None {
                    let parent = path.parent().unwrap();
                    let filename_str = filename.unwrap().to_str().unwrap().replace(":","%3A");
                    let enc_path = format!(
                        "{}/{}", 
                        parent.to_str().unwrap(), 
                        filename_str);
                    get_path(&enc_path, &mut art_paths, &art_name);
                }
                if art_paths.get(&art.name).is_none() {
                    println!("[-] Path for {} not found at {}", art.name, path_str);
                    // if not found, check others: mounted or ask user
                    // TODO: if collected path from live mount, check mounted
                    // if not found, ask the user to enter path
                    if silent {
                        // add path to hash
                        art_paths.insert(
                            art.name,
                            path_str.to_string()
                        );
                    } else {
                        get_users_path(&art_name, &mut art_paths);
                    }
                }
            }
        }
        // Return a hashmap of artefact paths
        art_paths
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
            get_glob_path(path_str, art_name, art_paths);
        }
    }

    fn get_glob_path(path_str: &String, art_name: &String, art_paths: &mut HashMap<String, String>) {
        // Get path from glob based path  
        for entry in glob(path_str).expect("Unable to read glob pattern") {
            match entry {
                Ok(path) => {
                    // add path to hash
                    art_paths.insert(
                        art_name.to_string(),
                        path.display().to_string()
                    );
                },
                Err(e) => println!("{:?}", e),
            }
        }
    }
}