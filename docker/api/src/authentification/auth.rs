use sqlx::{mysql, MySqlPool};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, get_current_timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use openssl::{kdf, rand::rand_bytes, symm::{Cipher, Crypter, Mode}};
use std::env;
use jsonwebtoken::errors::ErrorKind;
use passcheck::PasswordChecker;
use openssh::{Session, KnownHosts};
use std::sync::Arc;
use openssh_sftp_client::{Sftp, SftpOptions};
use crate::{borg_script::create_user, error::APIError};

// argon2id paramètres
const MEMORY_COST: u32 = 64*1024;
const ITERATION_COST: u32 = 3;
const PARALLELISM_COST: u32 = 4;
const HASH_LENGTH: usize = 32;

//Validiter d'un token Bearer
const EXPIRE_TIME: u64 = 60*60;
const REFRESH_TIME: u64 = 60*30;

const CLIENT_DIRECTORY: &str = "/srv/repos"; 

#[derive(Deserialize)]
pub struct Login{
    pub username: String,
    pub password: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials{
    pub exp: u64,
    pub id: String,
    pub kdf: String
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BearerState{
    /// Token à rafraîchir
    Refresh,
    /// Token valide
    Valid
}

#[derive(sqlx::FromRow)]
struct MysqlCredentials{
    id: String,
    encrypt_master_key_1: String,
    encrypt_master_key_2: String
}

#[derive(Clone)]
pub struct Auth{
    db: MySqlPool,
    pub ssh_connexion: Arc<Session>,
    pub sftp_connexion: Arc<Sftp>
}

impl Auth {
    pub async fn new() -> Auth{
        /* Initialisation des paramètre de connection à la base de donnée */
        let opt = mysql::MySqlConnectOptions::new()
        .host(&env::var("DB_HOST").expect("DB_HOST inexistant"))
        .password(&env::var("DB_PASSWORD").expect("DB_PASSWORD inexistant"))
        .port(match env::var("DB_PORT"){
            Ok(result)=> result.parse::<u16>().expect("Conversion du port de str à int a échoué"),
            Err(_)=> Err(()).expect("DB_PORT inexistant")
        })
        .username(&env::var("DB_USER").expect("DB_USER inexistant"))
        .database(&env::var("DB").expect("DB inexistant"));
        let session_ssh = Session::connect_mux("ssh://borg", KnownHosts::Add)
        .await.expect("Impossible de se connecter au serveur ssh");
        let session_sftp = Session::connect_mux("ssh://borg", KnownHosts::Add)
        .await.expect("Impossible de se connecter au serveur ssh");
        Self{
            db: MySqlPool::connect_with(opt).await.expect("Impossible de se connecter à la DB"),
            ssh_connexion: Arc::new(session_ssh),
            sftp_connexion: Arc::new(Sftp::from_session(session_sftp, SftpOptions::default()).await.expect("test"))
        }
    }
    pub async fn signup(&self, login: Login) -> Result<String, APIError> {
        let mut conn = self.db.acquire().await.expect("Impossible d'acquerir une connection DB");
        /* Vérification si l'utilisateur existe */
        let query = sqlx::query("SELECT username FROM Credentials WHERE username=?")
        .bind(login.username.as_str());
        let number_return_line: Vec<mysql::MySqlRow> = query.fetch_all(&mut *conn)
        .await.expect("Une erreur c'est produite");
        if number_return_line.len() > 0 {
            return Err(APIError::AlreadyExist);
        }

        // Vérification de la validité des Login
        if let Some(validation_state_login) = Auth::validation_login(&login){
            return Err(validation_state_login);
        }

        let username_for_encryption= Auth::corrrect_username_length(&login);
        log::info!("Username for encryption : {}", username_for_encryption);
        /* Création des id client */
        let kdf_client = match self.create_kdf(&login.password, &username_for_encryption).await {
            Ok(kdf_client) => kdf_client,
            Err(e) => {
                log::info!("Erreur lors de la création du kdf");
                return Err(e);
            }
        };
        let uuid = Uuid::new_v4().simple().to_string();

        // Création du répertoire utilisateur
        let _ = create_user::create_user(&uuid, self.ssh_connexion.clone()).await?;

        // Récupération de la clé borg 1
        let master_key_1_encrypted = create_user::get_master_key_1_encrypted(
            &uuid, 
            self.ssh_connexion.clone(), 
            self.sftp_connexion.clone()
        ).await?;
        // Récupérationd de la clé borg 2
        let master_key_2 = create_user::get_master_key_2(
            &uuid, 
            self.ssh_connexion.clone(), 
            self.sftp_connexion.clone()
        ).await?;

        // chiffrement de la clé borg 1
        let key_1_encrypted: String = self.encrypt_key(&kdf_client, master_key_1_encrypted)?;

        // chiffrement de la clé borg 2
        let key_2_encrypted: String = self.encrypt_key(&kdf_client, master_key_2.as_bytes().to_vec())?;

        if key_1_encrypted.len()>1200{
            log::info!("Erreur longueur de clé borg 1 encrypted signup: {}", key_1_encrypted.len());
            return Err(APIError::KDFError)
        }
        if key_2_encrypted.len()>1200{
            log::info!("Erreur longueur de clé borg 1 encrypted signup : {}", key_2_encrypted.len());
            return Err(APIError::KDFError)
        }

        /* Ajout de l'utilisateur dans la base de données */
        let query = sqlx::query("INSERT INTO Credentials \
        (id , username, encrypt_master_key_1, encrypt_master_key_2) VALUES(?,?,?,?)")
        .bind(&uuid)
        .bind(login.username.as_str())
        .bind(key_1_encrypted)
        .bind(key_2_encrypted);
        let _ = query.execute(&mut *conn).await.expect("l'utilisateur n'a pas pu être enregistrer");
        
        /* Renvoyer le cookie JWT */
        let credentials = Credentials{
            exp: get_current_timestamp() + EXPIRE_TIME, 
            id:uuid, 
            kdf:hex::encode(kdf_client)
        };
        match self.create_token(&credentials){
            Ok(token)=>return Ok(token),
            Err(e)=>return Err(e)
        };
    }

    fn encrypt_key(&self, kdf_client:&[u8], master_key: Vec<u8>)->Result<String, APIError>{
        /*Chiffrement clé_master_2 */
        const GCM_TAG_LEN: usize = 16;
        let mut iv = [0u8; 12];
        let _ = match rand_bytes(&mut iv){
            Ok(_)=>(),
            Err(_)=>{
                log::info!("Erreur lors de la génération aléatoire du iv");
                return Err(APIError::KDFError)
            }
        };

        let mut cipher = match Crypter::new(
            Cipher::aes_256_gcm(), 
            Mode::Encrypt, 
            kdf_client, 
            Some(&iv)
        ){
            Ok(cipher)=>cipher,
            Err(_)=>{
                log::info!("Erreur lors que la création du cypher");
                return Err(APIError::KDFError)
            }
        };
        let mut ciphertext = vec![0u8; master_key.len()+Cipher::aes_256_gcm().block_size()];
        let mut len_encrypted_data = match cipher.update(&master_key, &mut ciphertext){
            Ok(len)=>len,
            Err(_)=>{
                log::info!("Erreur lors de l'encryption de la clé");
                return Err(APIError::KDFError)
            }
        };
        len_encrypted_data += match cipher.finalize(&mut ciphertext[len_encrypted_data..]){
            Ok(len)=>len,
            Err(_)=>{
                log::info!("Erreur lors de la finalisation du chiffrement key_1");
                return Err(APIError::KDFError)
            }
        };
        let mut tag = [0u8; GCM_TAG_LEN];
        let _ = match cipher.get_tag(&mut tag){
            Ok(_)=>(),
            Err(_)=>{
                log::info!("Erreur lors de la récupération du tag GCM key_1");
                return Err(APIError::KDFError)
            }
        };
        ciphertext.truncate(len_encrypted_data);
        let mut final_encrypt = Vec::with_capacity(len_encrypted_data + iv.len() + GCM_TAG_LEN);
        final_encrypt.extend_from_slice(&iv);
        final_encrypt.extend_from_slice(&tag);
        final_encrypt.extend_from_slice(&ciphertext);
        let hex = hex::encode(final_encrypt);

        return Ok(hex)
    }

    pub async fn signin(&self, login:Login) -> Result<String, APIError>{
        /* Récupération clé master 2 */
        let mut conn = self.db.acquire().await.expect("Impossible d'acquerir une connection DB");
        let query = sqlx::query_as("SELECT id, encrypt_master_key_1, \
        encrypt_master_key_2 FROM Credentials WHERE username=?").bind(login.username.as_str());
        let result: Vec<MysqlCredentials> = query.fetch_all(&mut *conn).await.expect("Une erreur c'est produite");

        /* Vérification si l'utilisateur existe */
        if result.len() != 1 {
            return Err(APIError::NotSignup);
        }

        /* Création de la clé dériver */
        let username_for_encryption= Auth::corrrect_username_length(&login);
        let kdf_client = match self.create_kdf(&login.password, &username_for_encryption).await {
            Ok(kdf_client) => kdf_client,
            Err(e) => {
                return Err(e);
            }
        };
        /* Renvoyer le cookie JWT */
        let credentials = Credentials{
            exp: (get_current_timestamp() + EXPIRE_TIME), 
            id:result[0].id.clone(), 
            kdf:hex::encode(kdf_client)
        };
        let _ = match self.decrypt_master_2_key(&credentials).await{
            Ok(_)=>(),
            Err(e)=>return Err(e)
        };
        /* Vérification du mot de passe */
        match self.create_token(&credentials){
            Ok(token)=>return Ok(token),
            Err(e)=>return Err(e)
        };
        
    }
    fn validation_login(login: &Login)->Option<APIError>{
        let checker= PasswordChecker::<'static>::new()
        .min_length(12, Some("12"))
        .require_upper_lower(Some("A")) 
        .require_number(Some("1"))
        .require_special_char(Some("@"));
        if login.username.len() < 3{
            return Some(APIError::UsernameTooShort);
        }
        if login.username.len() > 255{
            return Some(APIError::UsernameTooLong);
        }
        if login.password.len() > 255{
            return Some(APIError::PasswordTooLong);
        }
        match checker.validate(login.password.as_str()) {
            Ok(_)=> return None,
            Err(e)=>{
                match e[0].as_str() {
                    "12" => return Some(APIError::PasswordTooShort),
                    "A" => return Some(APIError::MajusculeMissing),
                    "1" => return Some(APIError::NumberMissing),
                    "@" => return Some(APIError::SpecialCharMissing),
                    _ => return Some(APIError::InvalidPassword)
                }
            }
        }
    }

    fn corrrect_username_length(login:&Login)-> String{
        let mut username_for_encryption=String::from(login.username.clone());
        if username_for_encryption.len() < 8{
            let nbr_0_missing = 8 - username_for_encryption.len();
            for _ in 0..nbr_0_missing{
                username_for_encryption.push('0');
            }
            
        }
        return username_for_encryption;
    }

    pub async fn restore_master_key_file(&self, credentials: &Credentials)-> Result<(),APIError>{
        let filename = format!("{}/{}/.config/borg/keys/srv_repos_{}_repo", 
        CLIENT_DIRECTORY, credentials.id, credentials.id);

        //Vérification de la présence de la clé
        let output = match self.ssh_connexion.command("test")
        .args(["-f", filename.as_str()]).output().await{
            Ok(o)=>o,
            Err(_)=>{log::info!("Erreur connexion ssh restore_master_2_file");return Err(APIError::Ssh)}
        };
        let stdout = match String::from_utf8(output.stdout.clone()){
            Ok(out)=>out,
            Err(_)=>{
                log::info!("Erreur conversion stdout UTF8 restore_master_2_file");
                return Err(APIError::UTF8)
            }
        };
        let stderr = match String::from_utf8(output.stderr.clone()){
            Ok(out)=>out,
            Err(_)=>{
                log::info!("Erreur conversion stderr UTF8 restore_master_2_file");
                return Err(APIError::UTF8)
            }
        };
        if output.status.success(){
            log::info!("Erreur la clé borg existe déjà restore_master_2_file : \
             \nStdout: {}\nErreur: {}", stdout, stderr);
            return Ok(())//Err(APIError::Script)
        }
        // Déchiffrement de la clé Borg
        let master_key_2 =self.decrypt_master_2_key(&credentials).await?;
        // Création du fichier de la clé Borg
        let mut key_borg = match self.sftp_connexion.create(&filename).await {
            Ok(f)=>f,
            Err(e)=>{
            log::info!("Ouverture du fichier pour écrire la clé borg: {}", e.to_string());
            return Err(APIError::Sftp);
            }
        };
        match key_borg.write_all(&master_key_2).await{
            Ok(_)=>{
            log::info!("clé restauré {}", credentials.id);
            return Ok(())},
            Err(_)=> return Err(APIError::Write)
        };
    }

    pub async fn decrypt_master_1_key(&self, credentials: &Credentials)-> Result<Vec<u8>,APIError>{ 
        /* Récupération clé master 2 */
        let mut conn = self.db.acquire().await.expect("Impossible d'acquerir une connection DB");
        let query = sqlx::query_as("SELECT id, encrypt_master_key_1, \
        encrypt_master_key_2  FROM Credentials WHERE id=?").bind(credentials.id.as_str());
        let result: Vec<MysqlCredentials> = query.fetch_all(&mut *conn).await.expect("Une erreur c'est produite");
        if result.len() != 1 {
            log::info!("L'utilisateur {} n'est pas connue dans la base de données", credentials.id);
            return Err(APIError::NotSignup);
        }
        // Déchiffrement de la clé
        return Ok(Auth::decrypt_master_key(&result[0].encrypt_master_key_1,&credentials.kdf)?)
    }

    async fn decrypt_master_2_key(&self, credentials: &Credentials)-> Result<Vec<u8>,APIError>{  
        /* Récupération clé master 2 */
        let mut conn = self.db.acquire().await.expect("Impossible d'acquerir une connection DB");
        let query = sqlx::query_as("SELECT id, encrypt_master_key_1, \
        encrypt_master_key_2 FROM Credentials WHERE id=?").bind(credentials.id.as_str());
        let result: Vec<MysqlCredentials> = query.fetch_all(&mut *conn).await.expect("Une erreur c'est produite");
        
        // Déchiffrement de la clé
        return Ok(Auth::decrypt_master_key(&result[0].encrypt_master_key_2,&credentials.kdf)?)
    }
    fn decrypt_master_key(master_key: &String, kdf_client:&String)-> Result<Vec<u8>, APIError>{
        let iv_tag_ciphertext= match hex::decode(master_key){
            Ok(key)=> key,
            Err(_)=>{
                return Err(APIError::UTF8);
            }
        };
        let kdf_client = match hex::decode(kdf_client){
            Ok(key)=>key,
            Err(_)=>return Err(APIError::KDFError)
        };
        let (iv, tag_ciphertext) = iv_tag_ciphertext.split_at(12);
        const GCM_TAG_LEN:usize = 16;
        let (tag,ciphertext) = tag_ciphertext.split_at(GCM_TAG_LEN);
        let mut cipher = match Crypter::new(Cipher::aes_256_gcm(),Mode::Decrypt,&kdf_client, Some(&iv)){
            Ok(cipher)=>cipher,
            Err(_)=>{
                log::info!("Erreur lors que la création du cipher");
                return Err(APIError::KDFError)
            }
        };
        let _ = match cipher.set_tag(tag){
            Ok(_)=>(),
            Err(_)=>{
                log::info!("Erreur lors de l'injection du tag GCM key_1");
                return Err(APIError::KDFError)
            }
        };
        let mut data = vec![0u8; ciphertext.len()+Cipher::aes_256_gcm().block_size()];
        let mut len_data = match cipher.update(&ciphertext, &mut data){
            Ok(len)=>len,
            Err(_)=>{
                log::info!("Erreur lors du déchiffrement de la clé");
                return Err(APIError::KDFError)
            }
        };
        len_data += match cipher.finalize(&mut data[len_data..]){
            Ok(len)=>len,
            Err(_)=>{
                log::info!("Erreur lors du dechiffrement de la clé finale");
                return Err(APIError::KDFError)
            }
        };
        data.truncate(len_data);
        return Ok(data);

    }

    pub async fn delete_master_key_file(&self, uuid: &String)->Result<(), APIError>{
        let filename = format!("{}/{}/.config/borg/keys/srv_repos_{}_repo", CLIENT_DIRECTORY, uuid, uuid);
        let output = match self.ssh_connexion.command("shred").args(["-u", &filename]).output().await{
            Ok(o)=>o,
            Err(_)=>{
                log::info!("Erreur connexion ssh supression clé borg delete_master_key_2_file");
                return Err(APIError::Ssh)
            }
        };
        let stdout = match String::from_utf8(output.stdout.clone()){
            Ok(out)=>out,
            Err(_)=>{
                log::info!("Erreur conversion stdout UTF8 delete_master_2_key_file");
                return Err(APIError::UTF8)
            }
        };
        let stderr = match String::from_utf8(output.stderr.clone()){
            Ok(out)=>out,
            Err(_)=>{
                log::info!("Erreur conversion stderr UTF8 delete_master_2_key_file");
                return Err(APIError::UTF8)
            }
        };
        if ! output.status.success(){
            log::info!("Erreur lors de la supression de la clé borg : \nStdout: {}\nErreur: {}", stdout, stderr);
        }
        log::info!("Clé suprimer {}", uuid);
        return Ok(())
    }

    pub fn decode_token(token_jwt: &str) -> Result<Credentials, APIError>{
        let jwt_secret=env::var("JWT_SECRET").expect("JWT_SECRET inexistant");
        let validation = Validation::new(Algorithm::HS384);
        let token = match decode::<Credentials>(
                token_jwt,
                &DecodingKey::from_secret(jwt_secret.as_bytes()),
                &validation
            ){
                Ok(t)=>t,
                Err(e)=>{
                    log::info!("le decodage du token c'est mal déroulé");
                    if e.into_kind() ==  ErrorKind::ExpiredSignature{
                        log::info!("Le cookie Bearer a expiré");
                        return Err(APIError::Expired)
                    }else{
                        log::info!("Erreur inconnue concernant la validation du cookie");
                        return Err(APIError::ErrorBearer)
                    }
                }
            };
        let credentials =  Credentials { 
            exp: token.claims.exp, 
            id: token.claims.id, 
            kdf: token.claims.kdf };
        return Ok(credentials)
    }

    /* Vérifier token jwt */
    pub fn validation(&self,token_jwt: String)-> Result<(BearerState, (Option<String>, Credentials)), APIError>{
        let mut credentials = Auth::decode_token(token_jwt.as_str())?;
        if credentials.exp - REFRESH_TIME > get_current_timestamp(){
            return Ok((BearerState::Valid, (None, credentials)))
        }else{
            credentials.exp = get_current_timestamp()+EXPIRE_TIME;
            let token = self.create_token(&credentials)?;
            return Ok((BearerState::Refresh, (Some(token), credentials)))
        }
    }

    fn create_token(&self, credentials: &Credentials) -> Result<String, APIError>{
        /* Récupère la variable d'environnement */
        let jwt_secret=env::var("JWT_SECRET").expect("JWT_SECRET inexistant");

        let header = Header::new(Algorithm::HS384);
        match encode(&header, &credentials, &EncodingKey::from_secret(jwt_secret.as_bytes())){
            Ok(token) => return Ok(token),
            Err(e)=> {
                log::info!("Erreu lors de l'encodage du token create_token {}", e.to_string());
                return Err(APIError::EncodeToken)
            }
        };
    }

    async fn create_kdf(&self, password: &String, salt: &String) -> Result<[u8; HASH_LENGTH], APIError>{
        let password = password.as_bytes();
        let salt = salt.as_bytes();
        let mut out= [0u8; HASH_LENGTH];
        let _ = match kdf::argon2id(
            None, 
            &password, 
            &salt, 
            None, 
            None, 
            ITERATION_COST, 
            PARALLELISM_COST, 
            MEMORY_COST, 
            &mut out
        ){
            Err(_)=>{
                log::info!("Erreur lors de la création du kdf");
                return Err(APIError::KDFError)
            },
            Ok(_)=>return Ok(out)
        };
    }
}
