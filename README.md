/etc/apache2/sites-enabled/000-default.conf

###### *************************
In the server:

sudo useradd grader
cd /home/grader/
mkdir .ssh
touch ~/.ssh/authorized_keys
# Copy the public key generated in your localhost
vi ~/.ssh/authorized_keys
chmod 700 .ssh/
chmod 644 .ssh/authorized_keys
# Disable the user/psw access and allow only access using keys
# set PasswordAuthentication no
sudo vi /etc/ssh/sshd_config

# Allow the sudo role to the user grader
# login with a different sudo account
sudo vi /etc/sudoers.d/grader

# File content
# Created by cloud-init v. 17.2 on Sun, 13 Jan 2019 22:45:03 +0000
# User rules for ubuntu
grader ALL=(ALL) NOPASSWD:ALL


## Modify the Firewall rules

sudo ufw status
# disable all the incoming ports
sudo ufw default deny incoming
# allow all the outgoing ports
sudo ufw default allow outgoing
# allow ssh access
sudo ufw allow ssh
sudo ufw allow 2200/tcp
sudo ufw allow 80/tcp
sudo ufw allow 123/tcp

sudo ufw enable

#change the ssh port to 2200 in the following file
sudo vi /etc/ssh/sshd_config
#restart the ssh service
sudo service ssh restart

# Install apache2
sudo apt-get install apache2


# Install postgres  and create the user and database
grader@ip-172-26-3-190:~/my-udacity-crud-project$ sudo -u postgres createuser besttacos
grader@ip-172-26-3-190:~/my-udacity-crud-project$ sudo -u postgres createdb besttacos
grader@ip-172-26-3-190:~/my-udacity-crud-project$ sudo -u postgres psql
psql (9.5.14)
Type "help" for help.

postgres=# alter user besttacos with encrypted password 'xxxxx';


###### *************************
In your localhost:

sudo useradd grader
ssh-keygen
# previous command creates two files, your public and private key

#login into the server
ssh -p 2200 -i grader grader@34.218.66.67
