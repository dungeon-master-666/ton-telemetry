# TON Telemetry Service
## Building and running

  - First time: run `./setup.sh` to install required building tools: `docker`, `docker-compose`, `curl`.
  - Set needed environment variables (see [Configuration](#Configuration))
  - Set API keys for accessing info to `private/api_keys` file with format as in `api_keys_example.json`.
  - Set MongoDB password to `private/mongodb_password` file.
  - Set hash salt to `private/hash_salt` file.
  - Build services: `docker-compose build`.
  - Run services: `docker-compose up -d`.
  - (Optional) Generate SSL certificates: 
    - Connect to nginx container and run CertBot: `docker-compose exec nginx certbot --nginx`.
    - Enter email, agree with EULA, choose DNS name and setup SSL certs.
    - Restart NGINX: `docker-compose restart nginx`.
   - Stop services: `docker-compose down`. Run this command with`-v` flag to clear docker volumes (mongodb, nginx and ssl data).

## Configuration

The service supports the following environment variables for configuration.

- `TON_TELEMETRY_WEBSERVERS_WORKERS` *(default: 1)*

Number of webserver processes.


## Backup tasks

Daily backup:

- Create backup directory: `sudo mkdir /var/ton-backups`.
- Copy backup script to bin: `sudo cp ./backup.sh /usr/bin/ton-telemetry-backup`.
- Run `sudo crontab -e` and add the line `0 0 * * * ton-telemetry-backup >> /var/log/ton-telemetry-backup.log 2>&1`.
