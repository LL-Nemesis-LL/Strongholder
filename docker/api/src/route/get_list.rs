use actix_web::{post, HttpResponse, HttpRequest, web, Result};
use crate::authentification::auth::Auth;
use crate::error::APIError;
use crate::borg_script::list_archive::{list_archive, list_archive_content};
use serde::Deserialize;
use serde_json;

#[derive(Deserialize)]
struct Archive{
    archive_name: String
}


#[post("/get_list")]
async fn get_list(req: HttpRequest, auth: web::Data<Auth>, body: String)->Result<HttpResponse, APIError>{
    /* Extraction du cookie JWT */
    let Some(cookie) = req.cookie("Bearer") else{
        return Err(APIError::NoCookieBearer)
    };
    let credentials= Auth::decode_token(cookie.value())?;
    log::info!("User : {}", credentials.id);

    let _ = auth.restore_master_key_file(&credentials).await?;
    if body.len() == 0{
        let archives = list_archive(&credentials.id, auth.ssh_connexion.clone()).await?;
        auth.delete_master_key_file(&credentials.id).await?;
        return Ok(HttpResponse::Ok().json(archives))
    }else{
        let archive: Archive = match serde_json::from_str(body.as_str()){
            Ok(o)=>o,
            Err(_)=>{
                log::info!("Erreur lors de la conversion en json dans get_list");
                return Err(APIError::Json)
            }
        };
        let archive_files = list_archive_content(&credentials.id, auth.ssh_connexion.clone(), &archive.archive_name).await?;
        auth.delete_master_key_file(&credentials.id).await?;
        return Ok(HttpResponse::Ok().json(archive_files))
    };
            
    
}