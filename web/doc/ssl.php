<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

<h2>How to use monit with ssl</h2>

<h3>Author: <a
href="http://www.iei.tu-clausthal.de/methods/mitarbeiter_seite_en?staff_id=CH">Christian
Hopp</a></h3>

<ol>
                                              
<li><h3>Where to get openssl</h3>
               
<p>You can get the newest version of openssl at:

   <p><a href="http://www.openssl.org">http://www.openssl.org</a>

<p>In many cases your operating system already has a binary version of
openssl installed.


<li><h3>How do I turn on ssl support in monit</h3>

<p>To start monit's http server with ssl support, use the standard SET
HTTPD statement and add the keywords SSL ENABLE and specify the
location of the PEM encoded server certificate. This file should
contain the server's private key and certificate (see also: Generation
of a "pemfile").

<pre>
  SET HTTPD PORT 2812
      SSL ENABLE
      PEMFILE  /var/certs/monit.pem
      ADDRESS localhost
      ALLOW admin:bar
      ALLOW adminscomp.network.com
</pre>

<p>Start monit and connect to the monit http server over SSL via this
url: https://localhost:2812/

<p>You may also utilize ssl to allow monit to test a network connection
to a ssl enabled server. To do so, simply replace the TCP token with
the TCPSSL token. For instance, to check a web server running over ssl
(https) you can use the following command:

<pre>
check process https with pidfile /var/run/httpds.pid
      if failed port 443 
         type tcpssl protocol http 
      then alert
</pre>

<p>Port 443 is the standard HTTPS port.


<p>You can also setup monit to only allow clients with a certain
certificate. In other words, if a browser wants to connect to monit,
the browser will need to present a certificate known by monit. If it
is not known, monit will not accept the connection. The certificate
obtained from the client (browser) is checked against certificates in
a database file. This database file can be specified via the
CLIENTPEMFILE statement. It might look like this:

<pre>
  SET HTTPD PORT 2812
      SSL ENABLE 
      PEMFILE  /var/certs/monit.pem
      CLIENTPEMFILE  /var/certs/monit-client.pem
      ADDRESS localhost
      ALLOW admin:bar
      ALLOW adminscomp.network.com
</pre>

<p>The database file contains client certificates which are allowed to
access the monit httpd server.

<p>A certificate may also be self-signed. Normally a self-signed
certificate is not allowed, but you may explicit allow it by using the
ALLOWSELFCERTIFICATION statement.


<p>If you want to switch off SSL support for a while you may replace
the ENABLE keyword with DISABLE (without having to remove any other
SSL statements in the monit control file). Like so:

<pre>
  SET HTTPD PORT 2812
      SSL DISABLE
      PEMFILE  /var/certs/monit.pem
      CLIENTPEMFILE  /var/certs/monit-client.pem
      ALLOWSELFCERTIFICATION
      ADDRESS localhost
      ALLOW admin:bar
      ALLOW adminscomp.network.com
</pre>

<p>Finally, an overview of the http with ssl statement in monit:

<pre>
  SET HTTPD [PORT portnumber]
      [SSL [ENABLE|DISABLE]
       PEMFILE filename
       [CLIENTPEMFILE  filename]]
      ALLOWSELFCERTIFICATION
      ADDRESS hostname
      ALLOW [user:passwd|host]
      [ALLOW ...]
</pre>


               
<li><h3>How do I get my client certificate into a browser</h3>

<p>Here, the tricky part starts because we are dealing with a program
other than monit. (-:

<p>First, it is not just the certificate, you also have to provide the
private key of the certificate. This key SHOULD be different from the
key used by the monit's http server.

<p>You will need a key with a "client" purpose (in openssl it is
"nsCertType=client") or a key with no explicit purpose. Otherwise your
browser will not send the certificate.

<p>Netscape and its relatives (like Galeon or Mozilla) likes
certificates encoded in the PKCS12 format. If you have your client
certificate file PEM encoded you will need to convert it to PKCS12.

<p>So how do you convert a PEM encoded certificate to the PKCS12
format and import it into your browser? Simply use the openssl tool to
convert it:

<pre>
openssl pkcs12 -export -in monit_client.pem
                       -out monit_client.p12 \
                       -name "Monit" 
</pre>

<p>Finally you must import the certificate into your browser. In
mozilla you should use: Edit->Preferences->Privacy&Security, click on
the Manage Certificate button and in the window that pops up, click on
the Import button, then import the monit_client.p12 file.

<li><h3>I have turned off client certification but monit still complains</h3>

<p>If you turn of client certification in monit and a client is
sending a certificate then the monit server may complain with an error
like this:

<pre>
[MET Nov  4 14:41:10] SSL VERIFY ERROR: depth=0, error=[20] 
  'unable to get local issuer certificate': foo Subject
[MET Nov  4 14:41:10] HTTPD connection denied!
[MET Nov  4 14:41:10] Accept with SSL service has failed!
[MET Nov  4 14:41:10] http server: Cannot establish SSL connection -- Error 0
</pre>

<p>This simply means that the client provided a cert but monit wasn't
able to verify it. You can solve this by:

<ol>
<li>Configure your client not to send this certificate (e.g. delete it
from the Netscape's "Your Certificates".

<li>Turn on client certification and provide the certificate plus all
necessary CA certificates to monit in X.509 format (as pemfile).
</ol>

<li><h3>But... but... openssl had so many problems lately</h3>

<p>First of all, you can of course disable all ssl support in monit
and run monit without ssl if you are in doubt. If you want to build
monit without any SSL support, just run configure with

<pre>
  ./configure --without-ssl
</pre>

<p>If monit was already compiled with ssl support you don't need to
use it if you don't want to.  Simply use

<pre>
  SET HTTPD PORT &lt;port#&gt;
</pre>

<p>instead of

<pre>
  SET HTTPD PORT &lt;port#&gt;
	SSL [ENABLE]
	PEMFILE &lt;FILE&gt;
</pre>

<p>And remember, for security related software it is always wise to
keep it up to date. You should also keep an eye on advisories from
cert (CA) and other sources.



<li><h3>Generation of a "pemfile"</h3>

<p>First generate an openssl configuration (or if you have one use
it). It might look like this... it is just an example! (-:

<pre>
----- BEGIN:monit.cnf -----
# create RSA certs - Server

RANDFILE = ./openssl.rnd

[ req ]
default_bits = 1024
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type

[ req_dn ]
countryName = Country Name (2 letter code)
countryName_default = MO

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Monitoria

localityName                    = Locality Name (eg, city)
localityName_default            = Monittown

organizationName                = Organization Name (eg, company)
organizationName_default        = Monit Inc.

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Dept. of Monitoring Technologies

commonName                      = Common Name (FQDN of your server)
commonName_default              = server.monit.mo

emailAddress                    = Email Address
emailAddress_default            = root@monit.mo

[ cert_type ]
nsCertType = server
----- END:monit.cnf -----

In order to generate the actual pemfile just run these commands:
 
# Generates the private key and the certificate
/usr/local/bin/openssl req -new -x509 -days 365 -nodes \
        -config ./monit.cnf -out /var/certs/monit.pem \
        -keyout /var/certs/monit.pem

# Generates the  Diffie-Hellman Parameters
/usr/local/bin/openssl gendh 512 >> /var/certs/monit.pem

# Prints out the certificate information
/usr/local/bin/openssl x509 -subject -dates -fingerprint -noout \
                -in /var/certs/monit.pem
</pre>


<li><h3>How do I learn more about openssl</h3>

First have a look at the original documentation at openssl.org: <p> <a
href="http://www.openssl.org/docs/">http://www.openssl.org/docs/</a>

<p>When it comes to certs:
<p><a
href="http://gagravarr.org/writing/openssl-certs/">http://gagravarr.org/writing/openssl-certs/</a>

</ol>

<p>Have fun...! (-:



<?php include '../include/footer.html'; ?>
