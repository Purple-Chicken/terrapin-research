# Terrapin Research

## What is this repo? 

Repo contains the infra, services, notes, and proof-of-concept scripts for the research project. 

## Setting up the network 
To set up the sandbox network, you can run the following: 
```
git clone https://github.com/Purple-Chicken/terrapin-research.git 
cd terrapin-research.git 
docker compose up -d --build 
```
And Docker should create the network, including the custom server.

If needed, you can get a shell into Client, Attacker, and Server using the following lines: 
- Server:   `docker exec -it tp-server /bin/bash`
- Attacker: `docker exec -it tp-attack /bin/bash`
- Client:   `docker exec -it tp-client /bin/bash`


## Network diagram

We used Docker Compose to set up a sandbozed environment, which can work on any host which runs Docker. 

```
        Docker Network  
        10.5.0.0/24
  +-----------+-----------+
  |           |           |
 .30         .20         .10
Client     Attacker     Server
```
### Client

The client is running Debian Bullseye, which by default comes with a version of OpenSSH vulnerable to Terrapin. 
It is a mock client who attempts to connect to the server via different SSH methods: 
- Get user shell access into the server (Dropbear)
- Clone a private Gitea repo (custom Rust ssh client)
- SSH into the Rust SSH server using their downloaded Rust client (russh)
- Send a file to the server on the OpenSSH port using `rsync` (OpenSSH)


### Attacker 

The attacker is running the latest version of Kali Linux, a distribution of Linux focued on penetration testing. It contains tools and the capability to modify network packets, which is used for the MITM attack itself. 
It also will contain both the proof-of-concept method (script), and a full metasploit module to help automate the attack. 

### Server 

This server uses Debian Bookworm as the base image, and contains the following services vulnerable to this attack: 
- OpenSSH <9.6 
- Dropbear <2024.84 
- Gitea 1.21 (<1.21.3)
- Custom Rust SSH client/server (russh <0.40.2)

