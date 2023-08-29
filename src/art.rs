pub mod paths {
    use std::{path::Path, collections::HashMap};
    use glob::glob;
    use inquire::Text;
    use crate::{configs::config::Artefacts, art::paths};

    pub fn check_art(artefacts: Vec<Artefacts>, data_source: &String) -> HashMap<String, String> {
        let mut art_paths = HashMap::new();
        // TODO: Loop through all artefact paths and check if file/folder exists, if not check alt and legacy path
        for art in artefacts {
            let path_str = &art.path.replace(
                "{root}", 
                data_source
            );
            get_path(path_str, &mut art_paths, &art);
            if art_paths.get(&art.name).is_none() {
                println!("[-] Path for {} not found at {}", art.name, path_str);
                // if not found, check others: mounted or ask user
                // TODO: if collected path from live mount, check mounted
                // if not found, ask the user to enter path
                // TODO: don't prompt if silent flag set, and set default as the path in the hash
                get_users_path(&art, &mut art_paths);
            }
        }
        // Return a hashmap of artefact paths
        art_paths
    }

    fn get_users_path(art: &Artefacts, art_paths: &mut HashMap<String, String>) {
        let msg = format!("What is the file path of {}?", art.name);
        let path_ask = Text::new(&msg).prompt();
        let art_name = format!("{}", art.name);
        match path_ask {
            Ok(path_ask) => {
                get_path(&path_ask, art_paths, &art);
                if art_paths.get(&art_name).is_none() {
                    // user's path not found, adding to hash anyway
                    art_paths.insert(
                        art_name,
                        path_ask
                    );
                }
            },
            Err(_) => println!("An error occured when asking you for the path."),
        }
    }

    fn get_path(path_str: &String, art_paths: &mut HashMap<String, String>, art: &Artefacts) {
        let path_arg = Path::new(path_str);
        let art_name = format!("{}", art.name);
        if path_arg.exists() {
            // add path to hash
            art_paths.insert(
                art_name,
                path_arg.display().to_string()
            );
        } else {
            get_glob_path(path_str, art, art_paths);
        }
    }

    fn get_glob_path(path_str: &String, art: &Artefacts, art_paths: &mut HashMap<String, String>) {
        // Get path from glob based path  
        for entry in glob(path_str).expect("Unable to read glob pattern") {
            match entry {
                Ok(path) => {
                    let art_name = format!("{}", art.name);
                    // add path to hash
                    art_paths.insert(
                        art_name,
                        path.display().to_string()
                    );
                },
                Err(e) => println!("{:?}", e),
            }
        }
    }
}