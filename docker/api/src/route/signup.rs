use actix_web::{post,web, cookie::Cookie,HttpResponse};
use crate::authentification::auth::{Auth, Login};
use crate::error::APIError;

/*S'incrire */
#[post("/signup")]
async fn signup(id: web::Json<Login>, auth: web::Data<Auth>) -> Result<HttpResponse,APIError> {
    let login= Login{
        username: id.username.clone(), 
        password: id.password.clone()
    };
    // Création du Token
    let token = auth.signup(login).await?;

    let cookie = Cookie::build("Bearer", token)
    .path("/")
    .secure(true)
    .http_only(true)
    .finish();
    log::info!("User: {}", id.username);
    Ok(HttpResponse::Ok()
        .append_header(("Set-Cookie", cookie.to_string()))
        .finish())
    
}