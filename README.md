# Best Tacos
The [original project](https://github.com/womeat/my-udacity-crud-project) which works locally was modified to work with AWS lightsail.


## Deployment details
- IP: 34.218.66.67
- URL: http://34.218.66.67

## Software installed
- apache2
- postgresql
- libapache2-mod-wsgi
- python-pip

## Configuration made
1. Changes were made in the firewall to accept only the protocols:
- HTTP
- NTP
- SSH
2. Root access was disable in the server and a Key-based SSH authentication was enforced. The changes were made in the the file `/etc/ssh/sshd_config`.
3. The user `grader` was created with `sudo` permissions.
4. The postgres user `besttacos` and database `besttacos` where created
5. The script `myapp.wsgi` was and added to the mod_wsgi configuration `/etc/apache2/sites-enabled/000-default.conf`
`myapp.wsgi`
```
from app import app as application

import sys
sys.path.insert(0,'/home/grader/my-udacity-crud-project');
```
`/etc/apache2/sites-enabled/000-default.conf`
```
<VirtualHost *:80>
        ServerAdmin womeat@gmail.com
        DocumentRoot /var/www/html

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        WSGIDaemonProcess myapp threads=5 python-path=/home/grader/my-udacity-crud-project \
                python-home=/home/grader/my-udacity-crud-project/env

        WSGIProcessGroup myapp
        WSGIApplicationGroup %{GLOBAL}

        WSGIScriptAlias / /home/grader/my-udacity-crud-project/myapp.wgsi

        <Directory /home/grader/my-udacity-crud-project>
           WSGIProcessGroup myapp
           WSGIApplicationGroup %{GLOBAL}
           Require all granted
        </Directory>
</VirtualHost>

```
6. The SQLAlchemy engine in the python scripts were configure to work with Postgres.
```
engine = create_engine('postgres://besttacos:XXXXX@localhost:5432/besttacos')
```


# References
mod_wsgi (Apache)
- http://flask.pocoo.org/docs/1.0/deploying/mod_wsgi/
SQLAlchemy Engine Configuration
- https://docs.sqlalchemy.org/en/latest/core/engines.html
Firewall configuration (UFW)
- https://help.ubuntu.com/community/UFW
AWS lightsail
- https://lightsail.aws.amazon.com
