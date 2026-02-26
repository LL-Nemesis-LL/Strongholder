use openssh::Session;
use std::sync::Arc;
use crate::error::APIError;
use openssh_sftp_client::{file::File, Sftp};
const CLIENT_DIRECTORY: &str = "/srv/repos";
use serde::Deserialize;

#[derive(Deserialize)]
struct Restore{
    archive_name:String
}
#[derive(Debug, Deserialize)]
struct RestoreFile{
    archive_name:String,
    file_name:String
}

pub async fn dertermining_restore_mode(uuid: &String, body: &String, ssh_connexion: Arc<Session>, sftp_connexion:Arc<Sftp>)-> Result<(File, String), APIError>{
    let restore_file_name : RestoreFile = match serde_json::from_str(body.as_str()){
        Ok(restore_file_name)=>restore_file_name,
        Err(_)=>{
            let restore_archive_name :Restore = match serde_json::from_str(body.as_str()){
                Ok(restore)=>restore,
                Err(_)=>{
                    log::info!("erreur determining");
                    return Err(APIError::ValidInput)}
            };
            log::info!("restore");
            let file_name_only: Vec<&str> = restore_archive_name.archive_name.split("\\").collect();
            let file_name_only = file_name_only[file_name_only.len()-1];
            return Ok((restore(&uuid, &restore_archive_name.archive_name, ssh_connexion.clone(), sftp_connexion.clone()).await?, format!("{}.tar.gz", file_name_only)))
        }
    };
    log::info!("restore_file");
    return Ok((restore_file(&uuid, &restore_file_name.archive_name, &restore_file_name.file_name, ssh_connexion.clone(), sftp_connexion.clone()).await?, restore_file_name.file_name))
    
}

pub async fn restore(uuid: &String, archive:&String, ssh_connexion: Arc<Session>, sftp_connexion: Arc<Sftp>)->Result<File, APIError>{
    let output = match ssh_connexion.command("sudo").args(["/usr/local/sbin/restore.sh", uuid.as_str(), archive.as_str()]).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("Erreur ssh command restore");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 restore");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 restore");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors du restore\nstdout {}\n stderr: {}", &stdout, &stderr);
        return Err(APIError::Script)
    }
    let file_restore_path = format!("{}/{}/restore/{}.tar.gz",CLIENT_DIRECTORY, uuid, archive);
    match sftp_connexion.open(file_restore_path).await{
        Ok(f)=>return Ok(f),
        Err(_)=>{
            log::info!("Erreur Sftp connexion restore");
            return Err(APIError::Sftp)
        }
    }
}

pub async fn restore_file(uuid: &String, archive: &String, file_name:&String, ssh_connexion: Arc<Session>, sftp_connexion: Arc<Sftp>)->Result<File, APIError>{
    let output = match ssh_connexion.command("sudo").args(["/usr/local/sbin/restore.sh", uuid, archive, &file_name]).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("Erreur ssh command restore");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 restore");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 restore");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors du restore\nstdout {}\n stderr: {}", &stdout, &stderr);
        if let Some(code) = output.status.code(){
            log::info!("Erreur code {}", code);
        }
        
        return Err(APIError::NoFile)
    }
    let file_name_only: Vec<&str> = file_name.split("/").collect();
    let file_name_only = file_name_only[file_name_only.len()-1];
    let file_restore_path = format!("{}/{}/restore/{}",CLIENT_DIRECTORY, uuid, file_name_only);
    match sftp_connexion.open(file_restore_path).await{
        Ok(f)=>return Ok(f),
        Err(_)=>{
            log::info!("Erreur Sftp connexion restore");
            return Err(APIError::Sftp)
        }
    }
}