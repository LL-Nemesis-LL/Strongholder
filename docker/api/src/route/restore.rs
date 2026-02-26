use actix_web::{post, HttpResponse, HttpRequest,http::header::{ContentDisposition, DispositionType, DispositionParam}, web};
use crate::authentification::auth::Auth;
use crate::borg_script::restore::dertermining_restore_mode;
use crate::error::APIError;
use crate::stream_http::stream_http::StreamBuffer;
use openssh_sftp_client::file::TokioCompatFile;


#[post("/get_restore")]
async fn get_restore(req: HttpRequest, auth: web::Data<Auth>, body: String)-> Result<HttpResponse, APIError>{
    /* Extraction du cookie JWT */
    let Some(cookie) = req.cookie("Bearer") else{
        return Err(APIError::NoCookieBearer)
    };

    let credentials=Auth::decode_token(cookie.value())?;
    log::info!("User : {}", credentials.id);
    let _ = auth.restore_master_key_file(&credentials).await?;

    if body.len() == 0{
        return Err(APIError::ValidInput)
    }
    let (file, file_name) = dertermining_restore_mode(&credentials.id, &body, auth.ssh_connexion.clone(), auth.sftp_connexion.clone()).await?;
    let reader = TokioCompatFile::from(file);
    let stream = StreamBuffer::new(reader);
    auth.delete_master_key_file(&credentials.id).await?;
    let content_disposition = ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![
            DispositionParam::Filename(String::from(file_name))
        ],
    };
    return Ok(HttpResponse::Ok().insert_header(content_disposition).streaming(stream))
}

