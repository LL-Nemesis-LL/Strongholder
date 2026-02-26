use actix_web::{error,HttpResponse, cookie::{time::Duration,Cookie}};
use derive_more::derive::{Display, Error};


#[derive(Debug, Display, Error, PartialEq)]
pub enum APIError{
    NoFile,
    Metadata,
    NoCookieBearer,
    NoAuthAppData,
    Script,
    Ssh,
    Sftp,
    Write,
    ValidInput,

    //Convertion
    UTF8,
    Json,
    Usize,

    //Logup
    AlreadyExist,
    InvalidPassword,
    /// username inférieur à 5
    UsernameTooShort,
    /// Password length inférieur à 12
    PasswordTooShort,
    /// Pas de caractère spécial
    SpecialCharMissing,
    /// Pas de majuscule
    MajusculeMissing,
    /// Pas de chiffre
    NumberMissing,
    UsernameTooLong,
    PasswordTooLong,

    //Login
    NotSignup,
    KDFError,

    //Bearer
    /// Token à expiré
    Expired,
    EncodeToken,
    ErrorBearer


}

impl error::ResponseError for APIError{
    fn error_response(&self)->HttpResponse{
        let response = match *self{
            APIError::NoFile=>"600",
            APIError::Metadata=>"601",

            // Cas Généraux
            APIError::NoCookieBearer=>"101",
            APIError::NoAuthAppData=>"102",
            APIError::Script=>"103",
            APIError::Ssh=>"104",
            APIError::Sftp=>"105",
            APIError::ValidInput=>"106",

            // File
            APIError::Write=>"200",

            //Convertion
            APIError::UTF8=>"300",
            APIError::Json=>"301",
            APIError::Usize=>"302",

            //Logup
            APIError::AlreadyExist=>"1",
            APIError::UsernameTooShort=>"2",
            APIError::InvalidPassword=>"3",
            APIError::PasswordTooShort=>"4",
            APIError::SpecialCharMissing=>"5",
            APIError::MajusculeMissing=>"6",
            APIError::NumberMissing=>"7",
            APIError::UsernameTooLong=>"8",
            APIError::PasswordTooLong=>"9",

            // Login
            APIError::NotSignup=>"0",

            //Bearer
            APIError::Expired=>{
                let cookie = Cookie::build("Bearer", "")
                .path("/")
                .secure(true)
                .max_age(Duration::milliseconds(0))
                .http_only(true)
                .finish();
                return HttpResponse::Ok()
                .cookie(cookie)
                .body("503")
            },
            APIError::ErrorBearer=>"504",

            // token
            APIError::EncodeToken=>"700",
            //Encryption
            APIError::KDFError =>"400"
        };
        log::info!("{}", response);
        HttpResponse::BadRequest().body(response)
    }
}
