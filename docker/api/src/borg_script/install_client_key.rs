use openssh::Session;
use std::sync::Arc;
use openssh_sftp_client::Sftp;

pub async fn install_client_key(uuid: String, ssh_key:&String, filepath:String, ssh_connexion: Arc<Session>, sftp_connexion:Arc<Sftp>){
    // Crée le fichier
    let mut f = sftp_connexion.create(filepath.clone())
        .await.expect("Création du fichier à échouer");
    let _ = f.write(ssh_key.as_bytes()).await;
    let _ = f.close().await;

    /* Execution du script d'ajout de la clé ssh */
    let script_path=String::from("/usr/local/sbin/install_client_key.sh");
    match ssh_connexion.command("sudo").args([&script_path, &uuid, &filepath]).output().await{
        Ok(_)=>log::info!("script install_client_ssh"),
        Err(e)=>log::info!("{}", e.to_string())
    };
    // suppresion de la clé
    let _ = ssh_connexion.command("rm").arg(filepath).output().await;
}

