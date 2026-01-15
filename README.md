# siasmb
This is an SMB server integrated into the Sia decentralized cloud storage. Users can connect to it from their PCs and access the Sia storage like they would normally do with a regular remote drive.

## Prerequisites
* At least one `renterd` node running either locally or on a remote machine is required. The node needs to be funded, have the minimal required number of active storage contracts, and be accessible from the machine where the server is running.
Even though it is possible to use a single or multiple remote nodes, it is recommended to run the node locally, to avoid an overhead caused by the additional Internet traffic.
How to set up a `renterd` node is described here: [https://github.com/SiaFoundation/renterd](https://github.com/SiaFoundation/renterd).
* The SMB port 445 needs to be open on the machine where the server is running.

## Limitations
* At this moment, only the SMB dialects 2.0.2, 2.1, and 3.0 are supported. Newer dialects will potentially be supported in the future.
* Guest or anonymous access is not supported.

## Installing PostgreSQL
This section will assume you are running Ubuntu Server 24.04. On the other systems, the commands may be different.

Run the following command:
```
sudo apt install postgresql postgresql-contrib -y
```
Verify the installation:
```
sudo systemctl status postgresql
```
You should see something like:
```
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; enabled)
     Active: active (exited)
```
If it is inactive, start and enable it:
```
sudo systemctl enable --now postgresql
```
PostgreSQL creates a Unix user named postgres. Switch to it:
```
sudo -i -u postgres
```
Then open the PostgreSQL shell:
```
psql
```
You should see:
```
psql (16.x)
Type "help" for help.

postgres=#
```
Inside the `psql` prompt:
```
CREATE DATABASE <DATABASE>;
CREATE USER <USER> WITH ENCRYPTED PASSWORD <DB_PASSWORD>;
GRANT ALL PRIVILEGES ON DATABASE <DATABASE> TO <USER>;
\c <DATABASE>
GRANT USAGE ON SCHEMA public TO <USER>;
GRANT CREATE ON SCHEMA public TO <USER>;

```
Take a note of `<DATABASE>`, `<USER>`, and `<DB_PASSWORD>`, as you will need these values later on.
Exit `psql` with:
```
\q
```
Now we need to create the tables. Open the PostgreSQL shell under the newly created user:
```
psql -U <USER> -d <DATABASE> -h localhost
```
Enter `<DB_PASSWORD>` when prompted to.
Inside the `psql` prompt:
```
\i <PATH_TO_INIT.SQL>
```

## Running the Server
A config file, `siasmb.yml`, needs to be created in the directory where the server will be running. It should contain the following lines:
```
debug: false               # indicates whether to display the session ID and key for tools like Wireshark to decrypt the encrypted data
node: renterd              # indexd mode will be supported at a later step
maxConnections: 30         # the maximum number of connections accepted from the same IP within 10 minutes
api:
  port: 9999               # the port number that the API is listening on
  password: <API_PASSWORD> # the password to access the API
database:
  host: 127.0.0.1          # the address of the PostgreSQL server
  port: 5432               # the port number of the PostgreSQL server
  user: <USER>             # the name of the database user from the previous section
  password: <DB_PASSWORD>  # the password of the database user from the previous section; should be at least 4 characters long
  database: <DATABASE>     # the name of the PostgreSQL database from the previous section
  sslMode: disable         # the SSL mode of the PostgreSQL server
```
The server can be started either as a standalone executable or as a service (the latter is preferred). For example, on Linux:
```
sudo siasmb --dir=<PATH_TO_SIASMB.YML>
```
The superuser access is required because of the port 445 that the server is listening on.

Now, you need to register shares and add user accounts that will be accessing these shares.

To register a share, run (for example):
```
curl -u "":<API_PASSWORD> -X POST "http://127.0.0.1:9999/share" -d '{"name":"shared","serverName":"http://127.0.0.1:9980","password":"1234","bucket":"default","remark":"renterd"}'
```
To register a new account, run (for example):
```
curl -u "":<API_PASSWORD> -X POST "http://127.0.0.1:9999/account" -d '{"username":"test","password":"123","workgroup":"home"}'
```
To grant the account access to the share, run:
```
curl -u "":<API_PASSWORD> -X PUT "http://127.0.0.1:9999/share/shared/policy?username=test&workgroup=home&read=true&write=true&delete=true&execute=true"
```

## Security Considerations
An open TCP port 445 attracts thousands of attackers and those who look for a free storage. For this reason, guest and anonymous accesses are disabled. Even when the server is running on a private LAN, it should not be a problem to create a password-protected account like described above.

The server also has a built-in abuse protection. If 30 or more connections are detected from the same IP address within 10 minutes, this IP is permanently banned. This number of 30 can be configured in the config file (see above).

Also banned are those remote hosts, which continue sending SMB1 requests after receiving the initial SMB2 response from the server.

The bans are saved in the database, and the reason for the ban is provided. If a host ends up banned by mistake, it can be removed manually:
```
curl -u "":<API_PASSWORD> -X DELETE "http://127.0.0.1:9999/bans/<IP_OF_THE_REMOTE_HOST>"
```

## Connecting to the Server
In the guides below, `<SERVER_NET_ADDRESS>` stands for the network address of the SMB server, while `<SHARE_NAME>` is the name of the share registered earlier.

### Windows
1. Right-click on `This PC` icon and choose `Map network drive...` from the popup menu.
2. Type the address of the share in the `Folder` field (`\\<SERVER_NET_ADDRESS>\<SHARE_NAME>`). Pick any drive letter. Check the `Connect using different credentials` box, then click `Finish`.
3. In the next popup window, enter the user credentials (matching one of the registered accounts) and click `OK`.

Please note: Windows 2000/NT/XP and earlier are not supported. The earliest supported versions are Windows 7/Vista, because this is where the SMB2 protocol was first introduced.

### MacOS
1. In the `Finder` menu choose `Go -> Connect to Server...`.
2. Enter `smb://<SERVER_NET_ADDRESS>/<SHARE_NAME>` as the server name, then click `Connect`.
3. In the next popup window, choose `Connect As: Registered User` and enter the user credentials (matching one of the registered accounts, in form `<WORKGROUP>`\\`<USERNAME>`), then click `Connect`.

### Ubuntu GUI
1. In the file manager (e.g. Nautilus), navigate to `Other Locations`, enter `smb://<SERVER_NET_ADDRESS>/<SHARE_NAME>` in the `Enter server address` field, then click `Connect`.
2. In the next popup window, choose `Connect As: Registered User` and enter the user credentials (matching one of the registered accounts), then click `Connect`.

### Ubuntu CLI
1. If needed, install `cifs-utils` with
```
sudo apt install cifs-utils
```
2. Create a mount path with
```
sudo mkdir /mnt/sia
```
and change the ownership with
```
sudo chown $USER:$USER /mnt/sia
```
3. Mount the share with
```
sudo mount -t cifs //<SERVER_NET_ADDRESS>/<SHARE_NAME> /mnt/sia -o username=<USERNAME>,workgroup=<WORKGROUP>,password=<PASSWORD>,vers=2.0
```
4. To unmount, type
```
sudo umount /mnt/sia
```

## Proposed Testing Scenario
1. Connect to the share
2. Copy a file to the share root
3. Rename the file in the share root
4. Copy that file from the share root
5. Make a directory in the share root
6. Copy a file to that directory
7. Rename the file in that directory
8. Copy that file from that directory
9. Rename that directory
10. Delete that directory
11. Delete the file in the root directory
12. Copy a directory containing files to the share root
13. Copy that directory from the share root
14. Disconnect from the share

## Bug Reporting
Please do not hesitate to open an issue if you discover any bugs.

## Acknowledgement
This project was supported by a [Sia Foundation](https://sia.tech) grant.
