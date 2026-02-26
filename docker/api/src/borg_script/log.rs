use openssh::Session;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::error::APIError;
use crate::borg_script::list_archive::{ArchiveContent, list_archive, list_archive_content, Archives};

#[derive(Serialize, Deserialize)]
pub struct Logs{
    logs: Vec<String>
}

/*
{
    archives: [
        ArchiveData { archive: "2026-02-18_11-43-46", time: "2026-02-18T10:43:50.000000" }, 
        ArchiveData { archive: "2026-02-18_11-43-46_logs", time: "2026-02-18T10:44:01.000000"}
        ] 
}
[
    ArchiveContent { 
        archive_name: "2026-02-18_11-43-46", 
        archive_content: [
            ArchiveFile { type: "-", path: "mnt/d/2025-12-17 14-47-33.mkv", mtime: "2025-12-17T13:48:04.000000", size: 9806209 }
        ] 
    }, 
    ArchiveContent { 
        archive_name: "2026-02-18_11-43-46_logs", 
        archive_content: [
            ArchiveFile { type: "-", path: "home/hugo/.config/borg/logs/2026-02-18_11-43-46_71aea833849e4c258f17c381669b1c7c.log", mtime: "2026-02-18T10:43:59.864507", size: 1835 }
        ] 
    }
]
*/

pub async fn list_log_content(uuid: &String, ssh_connexion: Arc<Session>)->Result<Logs, APIError>{
    let mut archives_content = Vec::<ArchiveContent>::new();
    let mut archives = list_archive(uuid, ssh_connexion.clone()).await?;
    extract_log_archive(&mut archives);
    
    for archive_name in &archives.archives{
        archives_content.push(list_archive_content(uuid, ssh_connexion.clone(), &archive_name.archive).await?)
    }
    let mut logs_path = Vec::<String>::new();
    for archive in archives_content{
        logs_path.push(get_log_filename(archive, uuid)?);
    } 
    let mut logs = Logs{logs: Vec::<String>::new()};
    
    for i in 0..logs_path.len(){
        let _ = retore_log_file(uuid, ssh_connexion.clone(), &archives.archives[i].archive, &logs_path[i]).await?;
        let content = get_log_file(uuid, ssh_connexion.clone(), &archives.archives[i].archive, &logs_path[i]).await?;
        let _ = delete_log_file(uuid, ssh_connexion.clone(), &archives.archives[i].archive, &logs_path[i]).await?;
        logs.logs.push(content);
    }
    
    return Ok(logs)
}

fn extract_log_archive(archive: &mut Archives){
    for i in (0..archive.archives.len()).step_by(1).rev(){
        let filename = &archive.archives[i].archive;
        let Some((_,log)) = filename.split_at_checked(filename.len()-5)else {
            continue;
        };
        if log != "_logs"{
            archive.archives.remove(i);
        }
    }
}

fn get_log_filename(archive: ArchiveContent, uuid: &String)->Result<String, APIError>{
    let Some((first_part, _)) =  archive.archive_name.split_at_checked(archive.archive_name.len()-5) else{
        return Err(APIError::Script);
    };
    let log_filename = format!("{}_{}.log",first_part, uuid);
    let mut log_path = None;
    for file in archive.archive_content{
        if file.path.contains(&log_filename){
            log_path = Some(file.path);
            break;
        }
    }
    match log_path {
        Some(path)=>Ok(path),
        None=>{
            log::info!("Lors du listing des logs, le fichier {} n'a pas été trouvé dans l'archive {}", log_filename, archive.archive_name);
            Err(APIError::Script)}
    }
}

async fn retore_log_file(uuid: &String, ssh_connexion:Arc<Session>, archive_name: &String, log_path: &String)->Result<(), APIError>{
    // restoration du fichier
    let script_name = String::from("/usr/local/sbin/restore.sh");
    let output = match ssh_connexion.command("sudo").args([&script_name, uuid, archive_name, &log_path]).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("connexion ssh erreur");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 retore_log_file");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 retore_log_file");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors de la restoration du fichier de logs {}\nstdout {}\n stderr: {}", log_path ,&stdout, &stderr);
        return Err(APIError::Script)
    }
    Ok(())
}

async fn get_log_file(uuid: &String, ssh_connexion:Arc<Session>, archive_name: &String, log_path: &String)->Result<String, APIError>{
    // restoration du fichier
     let Some((first_part, _)) =  archive_name.split_at_checked(archive_name.len()-5) else{
        return Err(APIError::Script);
    };
    let output = match ssh_connexion.command("cat").arg(format!("/srv/repos/{}/restore/{}_{}.log", uuid, first_part, uuid)).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("connexion ssh erreur");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 get_log_file");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 get_log_file");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors de la récupération du fichier {}\nstdout {}\n stderr: {}", log_path ,&stdout, &stderr);
        return Err(APIError::Script)
    }
    Ok(stdout)
}
async fn delete_log_file(uuid: &String, ssh_connexion:Arc<Session>, archive_name: &String, log_path: &String)->Result<(), APIError>{
    // restoration du fichier
    let Some((first_part, _)) =  archive_name.split_at_checked(archive_name.len()-5) else{
        return Err(APIError::Script);
    };
    let output = match ssh_connexion.command("rm").arg(format!("/srv/repos/{}/restore/{}_{}.log", uuid, first_part, uuid)).output().await{
        Ok(o)=>o,
        Err(_)=>{log::info!("connexion ssh erreur");return Err(APIError::Ssh)}
    };
    let stdout = match String::from_utf8(output.stdout.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stdout UTF8 delete_log_file");
            return Err(APIError::UTF8)
        }
    };
    let stderr = match String::from_utf8(output.stderr.clone()){
        Ok(out)=>out,
        Err(_)=>{
            log::info!("Erreur conversion stderr UTF8 delete_log_file");
            return Err(APIError::UTF8)
        }
    };
    if ! output.status.success(){
        log::info!("Erreur lors de la supression du fichier {}\nstdout {}\n stderr: {}", log_path ,&stdout, &stderr);
        return Err(APIError::Script)
    }
    Ok(())
}