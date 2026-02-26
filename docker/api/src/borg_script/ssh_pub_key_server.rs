use openssh::Session;
use std::sync::Arc;
use crate::error::APIError;


pub async fn ssh_pub_key_server(ssh_connexion: Arc<Session>)->Result<String, APIError>{
    let mut output = match ssh_connexion.command("cat").arg("/etc/backup_server_keys/server_to_client_ed25519.pub").output().await{
        Ok(output)=>output,
        Err(_)=>{log::info!("Erreur lors de la connection ssh"); return Err(APIError::Ssh)}
    };
    if ! output.status.success(){
        let erreur = match String::from_utf8(output.stderr){
            Ok(err)=>err,
            Err(_)=>{
                log::info!("Erreur conversion");
                return Err(APIError::UTF8);
            }
        };
        log::info!("Erreur dans l'execution du cat du ssh_pub : {}", erreur);
        return Err(APIError::Script);
    }
    let len = output.stdout.len();
    if output.stdout[len - 1] == 10{
        output.stdout.pop();
    }
    let ssh_pub_key_server = match String::from_utf8(output.stdout){
        Ok(key)=>key,
        Err(_)=> {log::info!("Erreur convertion vers UTF8"); return Err(APIError::UTF8)}
    };
    return Ok(ssh_pub_key_server)
}