use actix_web::{post,web, cookie::Cookie, HttpResponse};
use crate::{authentification::auth::{Auth, Login}, error::APIError};

#[post("/signin")]
async fn signin(id: web::Json<Login>, auth: web::Data<Auth>) -> Result<HttpResponse,APIError>{
    let login= Login{
        username: id.username.clone(), 
        password: id.password.clone()
    };
    let token = match auth.signin(login).await{
        Ok(token)=>token,
        Err(e)=>return Err(e)
    };
    let cookie = Cookie::build("Bearer", token)
    .path("/")
    .secure(true)
    .http_only(true)
    .finish();
    log::info!("User: {}", id.username);
    Ok(HttpResponse::Ok()
    .append_header(("Set-Cookie", cookie.to_string()))
    .body(""))
}