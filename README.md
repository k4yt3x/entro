# ENTRO PROJECT

#### (OLD SADS PROJECT)
Migrated to ENTRO Project on 4/3/17

#
### Description
ENTRO is an active defense system for SSH. ENTRO uses the feature of SSH which the connection of SSH will not be disconnected by changing the port of restart ssh service. It will first generate a random hash, and then generate a port using a pre-shared algorithm on both the server side and the client side. It will then change the SSH port to the new generated port and this process every 10 seconds.

#
### Change Logs
#### Current Version: 1.1 beta
1. Renamed to ENTRO Project
2. ENTRO Client now uses configuration file
3. Added socket support

#
### Usage
Obtain a clone of the code
#### Server Side Install
~~~~
git clone https://github.com/K4YT3X/ENTRO.git
cd ENTRO/
mv entroServer.py /usr/bin/entroServer
chmod 755 /usr/bin/entroServer
chown root: /usr/bin/entroServer
~~~~
Then you will need to change the SEED constant
Otherwise other people will be able to connect to your server directly since they have the order or encoding

#
#### Client Side Install
~~~~
git clone https://github.com/K4YT3X/ENTRO.git
cd ENTRO/
mv entro.py /usr/bin/entro
chmod 755 /usr/bin/entro
chown root: /usr/bin/entro
~~~~

Now ENTRO client can be run with command "entro" in command line

#
#### Starting ENTRO Server
Use Screen command in linux to make ENTRO Server run in background
Run:
~~~~
screen
entroServer
~~~~
Then:
Press Ctrl+A
Press D

This will detach the windows and that window will then run in background even if the current windows is closed.

#
#### Configure ENTRO Client
When ENTRO is being stared for the first time, It will launch the setup wizard. Follow the instructions to setup server names and server addresses.

#
#### Connect to Server
This is very simple
Run
~~~~
entro
~~~~
First select the desired server from the list being displayed. Then the program will automatically fetch the HASH from server through either HTTP or Socket and decrypt it.
After that, linux built-in ssh program will take it from there
