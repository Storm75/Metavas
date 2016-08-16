#Install
sudo pip3 install progressbar
sudo pip3 install docopt


#Usage

Usage:

     ./metavas.py

     ./metavas.py -u [user] -w [password] -c [config] -n [hostname] -i [interface]

Example:

    metavas.py -u admin -w admin -c 0 -n 127.0.0.1 -i eth0




Please note that the "-c" config argument takes the configuration index input, not the name.
You can view these configuration indexes by starting the script without any argument.

Fresh install Configuration list indexes :

    [0] Discovery
    [1] empty
    [2] Full and fast
    [3] Full and fast ultimate
    [4] Full and very deep
    [5] Full and very deep ultimate
    [6] Host Discovery
    [7] System Discovery


##Script Variables

TARGET_UPLOAD            : Upload URL (ex: localhost/upload)
