use actix_web::{post, HttpResponse, HttpRequest, web, Result};
use crate::authentification::auth::Auth;
use crate::error::APIError;
use crate::borg_script::log::list_log_content;

#[post("/get_log")]
async fn get_log(req: HttpRequest, auth: web::Data<Auth>)->Result<HttpResponse, APIError>{
    /* Extraction du cookie JWT */
    let Some(cookie) = req.cookie("Bearer") else{
        return Err(APIError::NoCookieBearer)
    };
    let credentials= Auth::decode_token(cookie.value())?;
    log::info!("User {}", credentials.id);

    let _ = auth.restore_master_key_file(&credentials).await?;
    let logs = list_log_content(&credentials.id, auth.ssh_connexion.clone()).await?;
    auth.delete_master_key_file(&credentials.id).await?;
    return Ok(HttpResponse::Ok().json(logs))
}