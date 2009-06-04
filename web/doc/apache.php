<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

<h2>How to monitor Apache with Monit</h2>

<p><i>This HOWTO describe functionality available in monit version 4.5
and later</i></p> <h3>Author: <a
href="http://www.megapico.co.uk">David Fletcher</a></h3> <p>Version 1
- Jan 2005</p>

<ol>
                                              
<li><h3>Introduction</h3>
               
<p>The Monit "apache-status" protocol provides a way to monitor the
internal performance of an Apache web server, and to take action early
(i.e. while the server is still working) if something is going
wrong. It does this through Apache's mod_status, which needs to be
available to use these special Monit functions.

<p>The original development of the Apache-Status code was in response
to a failure of Apache's piped logging process which caused a server
to lock up. The server was in a chroot jail, and this prevented the
piped logging process from re-starting itself.  The original idea was
to use Monit to observe Apache from outside the chroot, and take
action if it spotted a problem.  However, following development of the
code it became clear that many other aspects of Apache can be
monitored, whether it is in a chroot jail or not.

<p><i>Important:</i> Since these tests uses mod_status, it depends on
the Apache server being able to respond. It should therefore be
combined with other monitoring to cover the case of a complete server
or connection failure.The tests will all work with the ExtendedStatus
directive On or Off.

<li><h3>Install mod_status</h3>

<p>Apache normally compiles with mod_status enabled and built in. To
access the status information the apache configuration file (often at
/etc/httpd/httpd.conf or /usr/apache/conf/httpd.conf) should include
these lines within one of your hosts or virtual hosts:

<pre>
&lt;Location /server-status&gt;
        SetHandler server-status
        Order deny,allow
        Deny from all
        Allow from 127.0.0.1
&lt;/Location&gt;
</pre>

<p>The Allow statement ensures that mod_status is only available on
the local machine, since it would be insecure to let everybody read
the information. If Monit is connecting from a different IP number
(i.e. if it is monitoring a remote machine) you should allow the IP
from which Monit will connect.
               
<li><h3>Test mod_status</h3>

<p>You can view the machine readable version of the Apache mod_status
output for your server by entering the standard URL in a browser
(Monit depends on this, rather than the human readable page):

<p><code>http://www.example.co.uk/server-status?auto</code></p>

<p>This will only work from the allowed IP numbers mentioned in the
section above. If everything is working well, you should see a page in
your browser like the one below:

<pre>
Total Accesses: 26
Total kBytes: 13
CPULoad: .0103093
Uptime: 970
ReqPerSec: .0268041
BytesPerSec: 13.7237
BytesPerReq: 512
BusyWorkers: 1
IdleWorkers: 5
Scoreboard:
____W_...........................................................
</pre>

<p>The important line is the Scoreboard, so don't worry if some of the
other lines are missing. The scoreboard is where Monit gets its
information about Apache. Each letter or dot represents an Apache
child process, and can be decoded using this key:

<pre>
"_" Waiting for Connection
"S" Starting up
"R" Reading Request
"W" Sending Reply
"K" Keepalive (read)
"D" DNS Lookup,
"C" Closing connection
"L" Logging
"G" Gracefully finishing
"I" Idle cleanup of worker
"." Open slot with no current process
</pre>

                         
<li><h3>Set up Monit</h3>

<p>Once mod_status is giving its output you can ask Monit to read this
information, and let you know if there is a problem.  A problem is
defined by using a percentage limit for the quantity monitored. This
is the percentage of Apache child processes which you allow in a
particular state before action is taken. A percentage is used rather
than a fixed number to let the monitoring "scale" with the rise and
fall in the number of Apache processes as the server load changes.

<p><b>Example 1:</b> You would like to restart the server if 60% or
more Apache child precesses are simultaneously writing to the
logs. Such a high percentage would probably indicate a problem with
the logs, which might be cleared by restarting the server. Add this to
/etc/monitrc:

<pre>
 check process apache with pidfile /var/run/httpd.pid
       start "/etc/init.d/httpd start"
       stop  "/etc/init.d/httpd stop"
       if failed host 127.0.0.1 port 80
          protocol apache-status loglimit > 60% 
       then restart
</pre>

<p><b>Example 2:</b> This configuration can be used to alert you if
25 percent or more of Apache child processes are stuck performing DNS
lookups:

<pre>
check process apache with pidfile /var/run/httpd.pid
       start "/etc/init.d/httpd start"
       stop  "/etc/init.d/httpd stop"
       if failed host www.example.co.uk port 80
          protocol apache-status dnslimit > 25% 
       then alert
</pre>

<p>In this case re-stating the server would be unlikely to solve the
problem, but it would be nice to know about it before the server comes
to a halt.

<li><h3>How the limits work</h3>

<p>Action can be triggered when each measured quantity rises above or 
falls below the percentage limit. However, with one exception all of the 
percentage limits are likely to be most useful if taken as the level 
above which action is triggered. As in the example above, an alert is 
sent when greater than 25% of the Apache child processes are performing 
a DNS lockup.

<p>The exception to this rule is when monitoring idle servers waiting 
for a connection. In this case it is much more useful to be alerted 
if there are too few free servers, so the action is best triggered 
when the measured level is less than the percentage limit.

<li><h3>What happens when the server is close to collapse?</h3>

<p>During testing it has been found that if httpd processes become
locked because, for example, they can't log, a request for the
server-status page generates a new child process, and gives a correct
report on the condition of the server. Only if there are very rapid
incoming connections, or a very low maximum number of httpd processes,
will the server-status page become inaccessible. In this case the
server will be re-started or an alert will be issued because the
connection to it will fail.

<li><h3>Are all these tests useful?</h3>

<p>Some tests are most useful as "alerts" rather than server restart
conditions. For example if DNS lookups are taking too much time you
want to be alerted, but restarting the Apache server will not
help. "or" conditions can be used to look at several conditions at
once, each with different limits. However, it is a waste of processing
power to monitor too many of the Apache parameters unless there is a
good reason. Most useful are likely to be the logging, free servers
and DNS lookup limits. The others are available for any special cases
where they become relevant.

<li><h3>Available tests</h3>
 
The following tests can be used: <code>loglimit, closelimit, dnslimit,
keepalivelimit, replylimit, requestlimit, startlimit, waitlimit
gracefullimit and cleanuplimit</code>. Several tests can be or'ed
together which we demonstrate in our final example:

<p>
<pre>
check process apache with pidfile /var/run/httpd.pid
      start "/etc/init.d/httpd start"
      stop  "/etc/init.d/httpd stop"
      if failed host www.example.co.uk port 80
         protocol apache-status dnslimit > 25% or 
                                loglimit > 80% or 
                                waitlimit < 20%
      then alert
</pre>

</ol>

<p><h3><code>Disclaimer</code></h3>

<p><i>Neither the author nor the distributors, or any other
contributor of this HOWTO are in any way responsible for physical,
financial, moral or any other type of damage incurred by following the
suggestions in this text.
</i>


<?php include '../include/footer.html'; ?>
