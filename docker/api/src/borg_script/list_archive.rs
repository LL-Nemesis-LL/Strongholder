use openssh::Session;
use std::sync::Arc;
use serde_json;
use serde::{Deserialize, Serialize};
use crate::error::APIError;

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchiveData{
    pub archive: String,
    pub time: String
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Archives{
    pub archives: Vec<ArchiveData>
}

pub async fn list_archive(uuid: &String, ssh_connexion: Arc<Session>,)->Result<Archives, APIError>{
    log::info!("List des archive pour le client : {}", uuid);
    let output = match ssh_connexion.command("sudo").args([String::from("/usr/local/sbin/list.sh"), uuid.to_string()]).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("connexion ssh erreur");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 list_archive");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 list_archive");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        if let Some(code) = output.status.code() {
            log::info!("code erreur {}", code);
        }
        log::info!("Erreur lors du listing des archives pour le client {}\nstdout {}\n stderr: {}", uuid,&stdout, &stderr);
        return Err(APIError::Script)
    }

    let archives: Archives = serde_json::from_str(&stdout).expect("serde_json");
    log::info!("Fin du listing pour le client{}", uuid);
    return Ok(archives)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArchiveContent{
    pub archive_name: String,
    pub archive_content: Vec<ArchiveFile>
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchiveFile{
    r#type: String,
    pub path: String,
    mtime: String,
    size:u64
}


pub async fn list_archive_content(uuid: &String, ssh_connexion: Arc<Session>, archive_name:&String)->Result<ArchiveContent, APIError>{
    let output = match ssh_connexion.command("sudo").args([String::from("/usr/local/sbin/list.sh"), uuid.to_string(), archive_name.clone()]).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("connexion ssh erreur");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 list_archive_content");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 list_archive_content");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors du listing du contenu de l'archive {}\nstdout {}\n stderr: {}", archive_name ,&stdout, &stderr);
        return Err(APIError::Script)
    }
    let mut archive_content = Vec::<ArchiveFile>::new();
    for line in stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let archive_file: ArchiveFile = match serde_json::from_str(line) {
            Ok(a)=>a,
            Err(_)=>{
                log::info!("Erreur lors de la conversion string to ArchiveFile list_archive_content");
                return Err(APIError::Json);
            }
        };
        archive_content.push(archive_file);
    }

    return Ok(ArchiveContent{archive_name: archive_name.to_string(), archive_content: archive_content})
}
