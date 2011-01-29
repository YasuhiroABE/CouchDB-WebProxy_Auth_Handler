README
======
A web server can be used for a front-end reverse proxy server of CouchDB.

[Official Wiki - Apache As a Reverse Proxy](http://wiki.apache.org/couchdb/Apache_As_a_Reverse_Proxy "Apache As a Reverse Proxy") tells you how to setup the apache as a reverse proxy server.

The remote user will be authenticated by the apache server, however, the local user can be access to couchdb without any authentication.
Because the wiki uses the admin-party setting.

The webproxy_authentication_handler can work with the default_authentication_handler.
It means that both the local user who authenticated by the default_authentication_handler and the remote user who authenticated by the reverse proxy will be authorized a reader or writer authority described at the _user document of CouchDB.

WebProxy_Authentication_Handler for CouchDB 1.0.1
-------------------------------------------------
T.B.D.

Appendix
--------
* [Japanese: Blog about webproxy authentication handler](http://yasu-2.blogspot.com/2010/11/couchdb-apachereverse-proxy_29.html "my blog site")
* [English: Blog about webproxy authentication handler](http://yasu-2.blogspot.com/2010/11/couchdb-how-to-use-reverse-proxy-server.html "my blog site, but my English is totally broken, I think.")
