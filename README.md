#SADS PROJECT

##Description
SADS is an active defense system for SSH. SADS uses the feature of SSH which the connection of SSH will not be disconnected by changing the port of restart ssh service. It will first generate a random hash, and then generate a port using a pre-shared algorithm on both the server side and the client side. lt will then change the SSH port to the new generated port and this process every 10 seconds.


##Usage
Obtain a clone of the code
####Server Side Install
~~~~
git clone https://github.com/K4YT3X/SADS.git
cd SADS/
mv sads_server.py /usr/bin/sads_server
chmod 755 /usr/bin/sads_server
chown root: /usr/bin/sads_server
~~~~


####Client Side Install
~~~~
git clone https://github.com/K4YT3X/SADS.git
cd SADS/
mv sads_server.py /usr/bin/sads
chmod 755 /usr/bin/sads
chown root: /usr/bin/sads
~~~~

Now SADS client can be run with command "sads" in command line


####Starting SADS Server
Use Screen command in linux to make SADS Server run in background
Run:
~~~~
screen
sads_server
~~~~
Then:
Press Ctrl+A
Press D

This will detach the windows and that window will then run in background even if the current windows is closed.


####Configure SADS Client
At the beginning of the program, there is a constant "SERVER_ADDRESS" which defines the server address. Change this to your server's IP or domain and the configuration is completed.
Now you are ready to connect to the server.

####Connect to Server
This is very simple
Run
~~~~
sads
~~~~
And the program will automatically fetch the HASH from server and decrypt it
Then linux built-in ssh program will take it from there