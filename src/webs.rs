pub mod web {
    use std::path::PathBuf;

    use actix_web::{middleware, web, App, HttpResponse, HttpServer, Result};
    use indicatif::MultiProgress;
    use serde::{Deserialize, Serialize};

    use crate::{configs::config, ops::wiskess};

    #[actix_web::main]
    pub async fn main() -> std::io::Result<()> {
        HttpServer::new(|| {
            App::new()
                .wrap(middleware::Logger::default())
                .configure(app_config)
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    }

    fn app_config(config: &mut web::ServiceConfig) {
        config.service(
            web::scope("")
                .service(web::resource("/").route(web::get().to(index)))
                .service(web::resource("/post1").route(web::post().to(handle_post_1))),
        );
    }

    async fn index() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../web/static/form.html")))
    }

    #[derive(Serialize, Deserialize)]
    pub struct MyParams {
        case_name: String,
        out_path: String,
        start_date: String,
        end_date: String,
        tool_path: PathBuf,
        ioc_file: String,
        silent: String,
        config: PathBuf,
        artefacts_config: PathBuf,
        data_source: String
    }

    /// Simple handle POST request
    async fn handle_post_1(params: web::Form<MyParams>) -> Result<HttpResponse> {

        let silent = match params.silent.as_str() {
            "on" => true,
            &_ => false,
        };

        let args = config::MainArgs {
            out_path: params.out_path.to_owned(),
            start_date: params.start_date.to_owned(),
            end_date: params.end_date.to_owned(),
            tool_path: params.tool_path.to_owned(),
            ioc_file: params.ioc_file.to_owned(),
            silent,
            out_log: PathBuf::new(),
            multi_pb: MultiProgress::new()
        };
        wiskess::start_wiskess(args, &params.config, &params.artefacts_config, &params.data_source);
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(format!(
                "You have submitted the following to be processed for {}:\n
                data_source: {}\nout_path: {}\nstart_date: {}\nend_date: {}\ntool_path: {}\n
                ioc_file: {}\nsilent: {}\nconfig: {}\nartefacts_config: {}\n",
                params.case_name,
                params.data_source, params.out_path, params.start_date, params.end_date, 
                params.tool_path.display(), params.ioc_file, silent, params.config.display(), 
                params.artefacts_config.display()
            )))
    }
}