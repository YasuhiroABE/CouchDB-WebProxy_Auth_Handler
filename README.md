<!-- -*- mode: markdown ; coding: utf-8 -*- -->

README
======
A web server can be used for a front-end reverse proxy server of CouchDB.

[Official Wiki - Apache As a Reverse Proxy](http://wiki.apache.org/couchdb/Apache_As_a_Reverse_Proxy "Apache As a Reverse Proxy") tells you how to setup the apache as a reverse proxy server.

The remote user will be authenticated by the apache server, however, the local user can be access to couchdb without any authentication.
Because the wiki uses the admin-party setting.

The webproxy\_authentication\_handler can work with the default\_authentication\_handler.
It means that both the local user who authenticated by the default\_authentication\_handler and the remote user who authenticated by the reverse proxy will be authorized their roles by the CouchDB.

                                            +Authorization: header
                         +---------------+  +X-Auth-CouchDB-Token: heade  +---------+ CouchDB will ;
    [remote user] ---->  |   web server  |  --------------------------->  | CouchDB | * set roles to the userCtx object.
              port:  80  |(reverse proxy)|          port: 5984   |        +---------+ * not check the remote user's password.
                 or 443  +---------------+                       |                    * check the local user's password.
                                                           [local user]           

WebProxy\_Authentication\_Handler for CouchDB 1.0.1
---------------------------------------------------

### Overview
The webproxy\_authentication\_handler assumes that a reverse proxy server will authenticate an user and pass through that username.

The handler supports the following HTTP headers to get the username.

* "Authorization: Basic"
* "Authorization: Digest"

The handler does not check the password at the /_users database, the handler just refer the roles of the username.

### Configuration Parameters

The handler adds three configuration parameters for local.ini.

* require\_authentication\_db\_entry (default: true)
* webproxy\_use\_secret (default: false)
* webproxy\_secret\_value (default: unset)

The default of the webproxy\_use\_secret is false, but to be true is highly recommended.

#### require\_authentication\_db\_entry (default: true)
If true, the handler requires the corresponding username at the /_users database.

#### webproxy\_use\_secret (default: false, optional)
If true, the handler requires the X-Auth-CouchDB-Token http header.

If the couchdb can be accessed from a remote host, it will protect the couchdb server from the fake http authorization header.

#### webproxy\_secret\_value (default: unset, optional)
If unset, the X-Auth-CouchDB-Token value is depending on just the secret parameter.

To improve the security, it will be used with the secret value to calucate the SHA1MAC.
Please see the example section.

Installation
------------
Recommended to recompile beam file from the source.

    $ cd apache-couchdb-1.0.1/src/couchdb/
    $ mv couch_httpd_auth.erl couch_httpd_auth.erl.orig
    $ git clone git://github.com/YasuhiroABE/CouchDB-WebProxy_Auth_Handler.git couch_httpd_auth.erl
    $ make

Finally, replace the **couch\_httpd\_auth.beam** with the installed one.

Otherwise, replace the *couch\_httpd\_auth.beam* with the *couch\_httpd\_auth.erl* as an instant way.

Example Settings
----------------

### Typical setting 

In the local.ini,

    [httpd]
    port = 5984
    bind_address = 127.0.0.1
    WWW-Authenticate = Basic realm="administrator"
    authentication_handlers = {couch_httpd_auth, default_authentication_handler}, {couch_httpd_auth, webproxy_authentication_handler}

    [couch_httpd_auth]
    require_valid_user = true
    require_authentication_db_entry = true

In the apache configuration file,

    <Location />
      ## Digest Auth
         AuthType Digest
         AuthName "CouchDB"
         AuthDigestDomain /
         AuthDigestProvider file
         AuthUserFile /etc/apache2/htdigest.db
      ## end of Digest Auth
      ## Basic Auth
      #  AuthType Basic
      #  AuthName "CouchDB"
      #  AuthUserFile /etc/apache2/htpassword.db
      ## end of Basic Auth
      Require valid-user
    </Location>

    <IfModule mod_proxy.c>
      ProxyPass / http://127.0.0.1:5984/
      ProxyPassReverse / http://127.0.0.1:5984/
    </IfModule>


### Enable X-Auth-CouchDB-Token

In the local.ini, add the secret parameter.

    [couch_httpd_auth]
    secret = 329435e5e66be809a656af105f42401e

In the apache configuration file, add the corresponding RequestHeader directive line like the following.

    <IfModule mod_proxy.c>
            <IfModule mod_headers.c>
                RequestHeader add X-Auth-CouchDB-Token "c21ec459f6a650dcf6907f2b52e611a069a7aeee"
            </IfModule>
            ProxyPass / http://127.0.0.1:5984/
            ProxyPassReverse / http://127.0.0.1:5984/
    </IfModule>

The value of the X-Auth-CouchDB-Token was calculated in the following way.

    $ erl -pa apache-couchdb-1.0.1/src/couchdb/
    1> nl(couch_util).
    abcast
    2> nl(crypto).
    abcast
    3> crypto:start().
    ok
    4> Secret = <<"329435e5e66be809a656af105f42401e">>.
    <<"329435e5e66be809a656af105f42401e">>
    5> couch_util:to_hex(crypto:sha_mac(Secret,Secret)).
    "c21ec459f6a650dcf6907f2b52e611a069a7aeee"

### Enable X-Auth-CouchDB-Token with webproxy\_secret\_value

In the local.ini, add the secret and webproxy\_secret\_value parameters.

    [couch_httpd_auth]
    secret = 329435e5e66be809a656af105f42401e
    webproxy_secret_value = 12ec701ca6c4c7fcaab1ef5db60450c323065c7d926f24c68ec48f7a896021b4

In the apache configuration file, change the corresponding token value.

    <IfModule mod_proxy.c>
            <IfModule mod_headers.c>
                RequestHeader add X-Auth-CouchDB-Token "6e5b2344de18fbe7d3e2358eb078fc7da0dac1ae"
            </IfModule>
            ProxyPass / http://127.0.0.1:5984/
            ProxyPassReverse / http://127.0.0.1:5984/
    </IfModule>

The token value was calculated by;
    
    $ erl -pa apache-couchdb-1.0.1/src/couchdb/
    1> nl(couch_util).
    abcast
    2> nl(crypto).
    abcast
    3> crypto:start().
    ok
    4> Secret = <<"329435e5e66be809a656af105f42401e">>.
    <<"329435e5e66be809a656af105f42401e">>
    5> Seeds = <<"12ec701ca6c4c7fcaab1ef5db60450c323065c7d926f24c68ec48f7a896021b4">
    5> couch_util:to_hex(crypto:sha_mac(Secret,Seeds)).
    "6e5b2344de18fbe7d3e2358eb078fc7da0dac1ae"

Appendix
--------
* [Japanese: Blog about webproxy authentication handler](http://yasu-2.blogspot.com/2010/11/couchdb-apachereverse-proxy_29.html "my blog site")
* [English: Blog about webproxy authentication handler](http://yasu-2.blogspot.com/2010/11/couchdb-how-to-use-reverse-proxy-server.html "my blog site, but my English is totally broken, I think.")

License
-------
The part of the webproxy\_authentication\_handler is licensed under the Apache License, Version 2.0.

    Copyright (C) 2010,2011 Yasuhiro ABE <yasu@yasundial.org>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
         http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

_EOF_
