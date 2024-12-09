# siasmb
This is an SMB server integrated into the Sia decentralized cloud storage. Users can connect to it from their PCs and access the Sia storage like they would normally do with a regular remote drive.

## Prerequisites
* At least one `renterd` node running either locally or on a remote machine is required. The node needs to be funded, have the minimal required number of active storage contracts, and be accessible from the machine where the server is running.
Even though it is possible to use a single or multiple remote nodes, it is recommended to run the node locally, to avoid an overhead caused by the additional Internet traffic.
How to set up a `renterd` node is described here: [https://github.com/SiaFoundation/renterd](https://github.com/SiaFoundation/renterd).
* The SMB port 445 needs to be open on the machine where the server is running.

## Limitations
* At this moment, only the SMB dialect 2.0.2 is supported. Newer dialects will potentially be supported in the future.
* Guest or anonymous access is not supported.

## Running the Server
Two text files need to be created in the directory where the server will be running: `accounts.json` and `shares.yml`.

`accounts.json` lists the credentials of all users that may access the server. It has the following structure:
```
{
  "accounts": [
    {
      "username": "<USERNAME_1>",
      "password": "<PASSWORD_1>"
    },
    {
      "username": "<USERNAME_2>",
      "password": "<PASSWORD_2>"
    },
    ...
    {
      "username": "<USERNAME_N>",
      "password": "<PASSWORD_N>"
    }
  ]
}
```
`shares.yml` lists the available shares and the accounts that may access each individual share. It has the following structure:
```
shares:
  - name: <SHARE_NAME>          # e.g. shared
    serverName: <SERVER_NAME>   # e.g. http://127.0.0.1:9980
    apiPassword: <API_PASSWORD> # the password you use to access the renterd API
    bucket: <BUCKET_NAME>       # e.g. default
    policies:
      - username: <USER_NAME_1> # a username from accounts.json
        read: true              # or false if you want to restrict the read access
        write: true             # or false if you want to restrict the write access
        delete: true            # or false if you want to restrict the delete access
        execute: true           # or false if you want to restrict the execute access
      - username: <USER_NAME_2>
        read: true
        write: true
        delete: true
        execute: true
      ...
      - username: <USER_NAME_N>
        read: true
        write: true
        delete: true
        execute: true
    remark: <REMARK>            # optional description of the share
```
If your `renterd` node has several buckets, each of them may be described as a separate share with different access policies.

The server can be started either as a standalone executable or as a service (the latter is preferred). For example, on Linux:
```
sudo siasmb --dir=<PATH_TO_ACCOUNTS.JSON_AND_SHARES.YML>
```
The superuser access is required because of the port 445 that the server is listening on.

## Security Considerations
An open TCP port 445 attracts thousands of attackers and those who look for a free storage. For this reason, guest and anonymous accesses are disabled. Even when the server is running on a private LAN, it should not be a problem to create a password-protected account like described above.

The server also has a built-in abuse protection. If 30 or more connections are detected from the same IP address within 10 minutes, this IP is permanently banned. This number of 30 can be configured by providing the `--maxConnections=<CONNECTION_LIMIT>` flag in the command line.

Also banned are those remote hosts, which continue sending SMB1 requests after receiving the initial SMB2 response from the server.

The bans are saved in the file `bans.json` in the directory where the configuration files are located, and the reason for the ban is provided. If a host ends up banned by mistake, it can be removed manually, after which the server needs to be restarted.

## Connecting to the Server
In the guides below, `<SERVER_NET_ADDRESS>` stands for the network address of the SMB server, while `<SHARE_NAME>` is the name of the share given in the file `shares.yml`.

### Windows
1. Right-click on `This PC` icon and choose `Map network drive...` from the popup menu.
2. Type the address of the share in the `Folder` field (`\\<SERVER_NET_ADDRESS>\<SHARE_NAME>`). Pick any drive letter. Check the `Connect using different credentials` box, then click `Finish`.
3. In the next popup window, enter the user credentials (matching one of the accounts from `accounts.json`) and click `OK`.

Please note: Windows 2000/NT/XP and earlier are not supported. The earliest supported versions are Windows 7/Vista, because this is where the SMB2 protocol was first introduced.

### MacOS
1. In the `Finder` menu choose `Go -> Connect to Server...`.
2. Enter `smb://<SERVER_NET_ADDRESS>/<SHARE_NAME>` as the server name, then click `Connect`.
3. In the next popup window, choose `Connect As: Registered User` and enter the user credentials (matching one of the accounts from `accounts.json`), then click `Connect`.

### Ubuntu GUI
1. In the file manager (e.g. Nautilus), navigate to `Other Locations`, enter `smb://<SERVER_NET_ADDRESS>/<SHARE_NAME>` in the `Enter server address` field, then click `Connect`.
2. In the next popup window, choose `Connect As: Registered User` and enter the user credentials (matching one of the accounts from `accounts.json`), then click `Connect`.

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
sudo mount -t cifs //<SERVER_NET_ADDRESS>/<SHARE_NAME> /mnt/sia -o username=<USERNAME>,password=<PASSWORD>,vers=2.0
```
4. To unmount, type
```
sudo umount /mnt/sia
```

## Bug Reporting
Please do not hesitate to open an issue if you discover any bugs.

## Acknowledgement
This project was supported by a [Sia Foundation](https://sia.tech) grant.
