pub mod web {
    use std::{
        any::{Any, TypeId}, path::{Path, PathBuf}
    };

    use actix_multipart::form::{
            tempfile::{TempFile, TempFileConfig}, text::Text, MultipartForm
        };
    use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder, Result};
    use indicatif::MultiProgress;
    use struct_iterable::Iterable;

    use crate::{configs::config, init::scripts, ops::wiskess};

    use askama_actix::Template;

    #[derive(Template)]
    #[template(path = "wiskess_task.html")]
    struct WiskessTask {
        items: Vec<String>,
    }

    #[derive(Debug, MultipartForm)]
    struct UploadForm {
        ioc_file: TempFile,
        case_name: Text<String>,
        out_path: Text<String>,
        start_date: Text<String>,
        end_date: Text<String>,
        silent: Text<String>,
        config: Text<String>,
        artefacts_config: Text<String>,
        data_source: Text<String>,
    }
    #[derive(Debug, MultipartForm)]
    struct WhippedForm {
        ioc_file: TempFile,
        case_name: Text<String>,
        local_storage: Text<String>,
        in_link: Text<String>,
        out_link: Text<String>,
        start_date: Text<String>,
        end_date: Text<String>,
        config: Text<String>,
        artefacts_config: Text<String>,
        update: Text<String>,
        keep_evidence: Text<String>,
        data_source_list: Text<String>,
    }

    struct AppState {
        tmp_dir: PathBuf,
        tool_path: PathBuf,
        config_path: PathBuf,
    }

    #[actix_web::main]
    pub async fn main(tool_path: PathBuf) -> std::io::Result<()> {
        env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

        let tmp_path = Path::new(tool_path.parent().unwrap()).join("tmp");
        log::info!("creating temporary upload directory: {}", tmp_path.display());
        std::fs::create_dir_all(&tmp_path)?;

        let address = "127.0.0.1";
        let port = 8080;
        log::info!("Starting WebUI on http://{address}:{port}");
        HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default())
                .app_data(TempFileConfig::default().directory("./tmp"))
                .app_data(web::Data::new(AppState {
                    tmp_dir: tmp_path.to_owned(),
                    tool_path: tool_path.to_owned(),
                    config_path: Path::new(&tool_path.parent().unwrap()).join("config"),
                }))
                .configure(app_config)
        })
        .bind((address, port))?
        .run()
        .await
    }

    fn app_config(config: &mut web::ServiceConfig) {
        config.service(
            web::scope("")
                .service(web::resource("/").route(web::get().to(index)))
                .service(web::resource("/wiskess_form").route(web::get().to(wiskess_get)))
                .service(web::resource("/wiskess_sent").route(web::post().to(wiskess_post)))
                .service(web::resource("/whipped_form").route(web::get().to(whipped_get)))
                .service(web::resource("/whipped_sent").route(web::post().to(whipped_post))),
        );
    }

    /// convert a struct of diff types to a vector in format: name: value
    fn struct_to_vec_whip(args: &config::WhippedArgs) -> Vec<String> {
        let mut items = vec![];
        for (name, value) in args.iter() {
            format_any(value, &mut items, name);
        }
        items
    }

    /// convert a struct of diff types to a vector in format: name: value
    fn struct_to_vec_main(args: &config::MainArgs) -> Vec<String> {
        let mut items = vec![];
        for (name, value) in args.iter() {
            format_any(value, &mut items, name);
        }
        items
    }

    fn format_any(value: &dyn Any, items: &mut Vec<String>, name: &str) {
        // exclude any items that aren't useful here
        if name == "multi_pb" {
            return
        } 

        if value.type_id() == TypeId::of::<String>() {
            items.push(format!("{}: {}", name, value.downcast_ref::<String>().unwrap()));
        } else if value.type_id() == TypeId::of::<PathBuf>() {
            items.push(format!("{}: {}", name, value.downcast_ref::<PathBuf>().unwrap().display()));
        } else if value.type_id() == TypeId::of::<bool>() {
            items.push(format!("{}: {}", name, value.downcast_ref::<bool>().unwrap()));
        } else {
            items.push(format!("{}: {:#?}", name, value));
        }
    }
    
    /// save ioc file to tmp folder with casename and timestamp prefixed
    fn save_file(state: &web::Data<AppState>, case_name: &String, ioc_file: TempFile) -> PathBuf {
        let ioc_path = state.tmp_dir.join(
            format!("{}_{}",
                case_name,
                ioc_file.file_name.unwrap()
            )
        );
        log::info!("saving to {}", ioc_path.display());
        ioc_file.file.persist(&ioc_path).unwrap();
        ioc_path
    }

    /// main page
    async fn index() -> Result<HttpResponse> {
    // async fn index() -> impl Responder {
    //     HelloTemplate { name: "Gavin"}
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../web/static/index.html")))
    }

    /// form for submitting to the wiskess command
    async fn wiskess_get() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../web/static/wiskess.html")))
    }

    /// form for submitting to the whipped command
    async fn whipped_get() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../web/static/whipped.html")))
    }

    /// handle POST request for wiskess
    async fn wiskess_post(
        state: web::Data<AppState>,
        MultipartForm(params): MultipartForm<UploadForm>,
    // ) -> Result<impl Responder, Error> {
    ) -> impl Responder {
        
        log::info!("Received request to run wiskess");
        
        let silent = match params.silent.as_str() {
            "on" => true,
            &_ => false,
        };
                
        // set the paths of the chosen configs
        let config = state.config_path.join(&params.config.to_string());
        let artefacts_config = state.config_path.join(&params.artefacts_config.to_string());
        
        let ioc_path = save_file(&state, &params.case_name, params.ioc_file);
        
        let ioc_filename = ioc_path.into_os_string().into_string().unwrap();
        
        let args = config::MainArgs {
            out_path: params.out_path.to_string(),
            start_date: params.start_date.to_string(),
            end_date: params.end_date.to_string(),
            tool_path: state.tool_path.clone(),
            ioc_file: ioc_filename,
            silent,
            collect: true,
            out_log: PathBuf::new(),
            multi_pb: MultiProgress::new()
        };

        let mut items = struct_to_vec_main(&args);
        items.push(format!("Process config: {}", config.display()));
        items.push(format!("Artefacts config: {}", artefacts_config.display()));
        items.push(format!("Data source: {}", params.data_source.to_string()));

        let msg = format!("You have submitted the following to be processed: {}.", 
            items.join("; ")
        );
        log::info!("{}", msg);

        let _res = actix_web::rt::spawn( async move {
            wiskess::start_wiskess(args, &config, &artefacts_config, &params.data_source);
        });

        // Cookie::new("case_name", params.case_name.to_string());
        // Cookie::new("out_path", params.out_path.to_string());
        
        let html = WiskessTask {
            items
        };
        html
    }
    
    /// handle post for whipped
    async fn whipped_post(
        state: web::Data<AppState>,
        MultipartForm(params): MultipartForm<WhippedForm>
    ) -> impl Responder {
        
        log::info!("Received request to run whipped");

        let keep_evidence = match params.keep_evidence.as_str() {
            "yes" => true,
            &_ => false,
        };
        let update = match params.update.as_str() {
            "yes" => true,
            &_ => false,
        };
        
        // set the paths of the choose configs
        let config = state.config_path.join(&params.config.to_string());
        let artefacts_config = state.config_path.join(&params.artefacts_config.to_string());

        let ioc_path = save_file(&state, &params.case_name, params.ioc_file);

        let ioc_filename = ioc_path.into_os_string().into_string().unwrap();

        // pre-process the data_source_list, splitting by new lines and spaces

        // put the args into a whipped structure
        let args = config::WhippedArgs {
            config: config,
            artefacts_config,
            data_source_list: params.data_source_list.to_string(),
            local_storage: params.local_storage.to_string(),
            start_date: params.start_date.to_string(),
            end_date: params.end_date.to_string(),
            ioc_file: ioc_filename.clone(),
            in_link: params.in_link.to_string(),
            out_link: params.out_link.to_string(),
            update,
            keep_evidence,
        };

        let items = struct_to_vec_whip(&args);

        let msg = format!("You have submitted the following to be processed: {}", items.join("; "));
        log::info!("{}", msg);
        
        let _res = actix_web::rt::spawn( async move {
                scripts::run_whipped(&state.tool_path, args);
        });

        // Cookie::new("case_name", params.case_name.to_string());
        // Cookie::new("out_path", params.out_path.to_string());

        let html = WiskessTask {
            items
        };
        html
    }
}