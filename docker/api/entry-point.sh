#!/bin/sh
HOME_DIRECTORY=/home/api
SSH_DIRECTORY=$HOME_DIRECTORY/.ssh
cat <<EOF > $SSH_DIRECTORY/config
Host borg
    IdentityFile $SSH_DIRECTORY/id_ed25519
    HostName borg
    User api
    Port 22
EOF
chmod 600 -R $SSH_DIRECTORY/*
chown api:api -R $SSH_DIRECTORY
chown api:api /usr/local/bin/strongholer
su api -c /usr/local/bin/strongholer