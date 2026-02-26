use actix_web::{HttpRequest, HttpResponse, post,web, App, HttpServer, middleware};
use actix_web::middleware::Logger;
mod authentification;
use crate::authentification::auth::Auth;
use crate::authentification::middleware_auth;
use crate::error::APIError;
use serde_json;
mod error;
mod route;
mod borg_script;
mod stream_http;
use crate::route::{get_list, get_repot_key, get_ssh_pub_key_server, send_ssh_key, send_ssh_key_tunnel, signin, signup, restore, get_log};


#[post("/imaconnected")]
async fn imaconnected(req: HttpRequest) -> Result<HttpResponse, APIError>{
    /* Extraction du cookie JWT */
    let Some(cookie) = req.cookie("Bearer") else{
        return Err(APIError::NoCookieBearer)
    };

    let credentials= Auth::decode_token(cookie.value())?;
    let Ok(credentials_json) = serde_json::to_string(&credentials)else{
        return Err(APIError::Json)
    };
    return Ok(HttpResponse::Ok().content_type("application/json").body(credentials_json))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth = Auth::new().await;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    log::info!("connection db et ssh réussi");
    
    HttpServer::new(move || {
        App::new()
        .app_data(web::Data::new(auth.clone()))
        .service(
            web::scope("/api")
            .wrap(middleware::from_fn(middleware_auth::authentification_middleware))
            .wrap(Logger::default())
            .service(signup::signup)
            .service(signin::signin)
            .service(imaconnected)
            .service(send_ssh_key::send_ssh_key)
            .service(send_ssh_key_tunnel::send_ssh_key_tunnel)
            .service(get_repot_key::get_repot_key)
            .service(get_list::get_list)
            .service(get_ssh_pub_key_server::get_ssh_pub_key_server)
            .service(restore::get_restore)
            .service(get_log::get_log)
        )
    })
    .bind(("0.0.0.0", 8080)).expect("exit notime to play")
    .run()
    .await
}
