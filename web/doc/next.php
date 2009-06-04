<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

<h2>Plans for future monit releases</h2>

<h3><u>Introduction:</u></h3>

This document is a draft for future releases of monit. Each feature
item is listed with the responsible for the implementation, the
current progress (the color will go from blue to green) and how we
judge the importance of this feature (high, medium, low).
<p>
Items marked with a <i>low</i> importance will not make it into the
nearest monit release, but maybe in a future release. If you would
like to change anything or add stuff to this list join the <A HREF=
"http://mail.freesoftware.fsf.org/mailman/listinfo/monit-general">monit
mailing lists</A> and let us know.

<br>
<p>

<h3><u>Feature list:</u></h3>

<div style="background: #EFF7FF; padding: 10px;">
<b>Done</b>
<ul style="list-style-type: square;">
  <li><a href="#31">Add the MONIT_DESCRIPTION environment variable for exec</a></li>
  <li><a href="#38">Start/stop/exec method timeouts</a></li>
</ul>
<b>In progress</b>
<ul style="list-style-type: square;">
    <li><a href="#33">Call out to an external script or program</a></li>
</ul>
<b>Planned</b>
<ol>
  <li><a href="#02">MySQL authentication test</a></li>
  <li><a href="#32">Customize monit log file output</a></li>
  <li><a href="#03">Event traceback</a></li>
  <li><a href="#06">URL request for protocol tests (like ldap, ftp, etc.)</a></li>
  <li><a href="#07">Network interfaces health and load monitoring</a></li>
  <li><a href="#08">Filesystem load average tests</a></li>
  <li><a href="#09">Filesystem related caches test</a></li>
  <li><a href="#34">Timeofday actions</a></li>
  <li><a href="#10">IPv6 support</a></li>
  <li><a href="#11">S.M.A.R.T capable devices monitoring support</a></li>
  <li><a href="#18">ARP (MAC address) tests in host services</a></li>
  <li><a href="#19">SCSI ping support for device test</a></li>
  <li><a href="#21">Action list support and optional service name target</a></li>
  <li><a href="#26">Support for status listing by service group</a></li>
  <li><a href="#27">Support for hard service dependency</a></li>
  <li><a href="#28">Matching timeout rule should set the service state to 'timed out'</a></li>
  <li><a href="#29">Display filesystem type</a></li>
  <li><a href="#30">Log full start/stop/exec command</a></li>
  <li><a href="#36">Allow to override the implicit action on some events</a></li>
  <li><a href="#39">Handle multiple lines matching the pattern in single MATCH statement as single group with one action</a></li>
  <li><a href="#40">Add the start/stop/restart throttling</a></li>
  <li><a href="#41">Log the start/stop/exec program output</a></li>
  <li><a href="#42">Support timestamp test relative to other file</a></li>
  <li><a href="#43">Watch process' filedecriptors count</a></li>
</ol>
</div>


<table id="feature">
<tr>
<td colspan=2 >
<h3><a name="02">MySQL authentication test</a></h3>

Allow specifying a username and password in the mysql protocol test for
authentication. Monit is currently supporting anonymous authentication,
but in those cases where anonymous authentication is disabled this may
be useful.

<p>Example statement to be used in monitrc:</p>

<pre> 
  if failed host 192.168.1.1 port 3306 
     protocol mysql://user:password@localhost:3306/mydatabase 
  then restart 
</pre>

<p>See e.g. http://www.redferni.uklinux.net/mysql/MySQL-Protocol.html for a description of the the MySQL protocol</p>

</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>MEDIUM</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2 >
<h3><a name="32">Customize monit log file output</a></h3>

Use the same approach as the apache project for configuring log file output. 
The log file format will be set using a global set-statement, <p>

<code>set logformat "%h %l %u %t %&gt;s %b"</code> 

<p>and where applicable the format specifiers match those of apache log file.

</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>MEDIUM</b></td>
</tr>
</table>

<table id="feature">
<tr>
<td colspan=2 >
<h3><a name="33">Call external script from monit and check return value</a></h3>

We plan to support two levels of running an external script. 
<ol>
<li>As a full 'check status' service 
<li>As an if test. 
</ol>

Here is the syntax defined more formal (keywords in uppercase) for those two cases:
<pre>
1) CHECK STATUS OF name WITH PATH "/path/to/script"
[[AND] TIMEOUT AFTER X sec]
IF FAILED THEN
{ALERT|MONITOR|UNMONITOR|START|STOP|RESTART|EXEC}
[ELSE
        {ALERT|MONITOR|UNMONITOR|START|STOP|RESTART|EXEC}
        ]
[ALERT ..]
[EVERY ..]
[DEPENDS ON ..]
[GROUP ..]

2) check X ...
IF FAILED STATUS OF [SCRIPT|PROGRAM] "/path/to/script"
[AND TIMEOUT AFTER X sec] THEN
{ALERT|MONITOR|UNMONITOR|START|STOP|RESTART|EXEC}
ELSE
{ALERT|MONITOR|UNMONITOR|START|STOP|RESTART|EXEC}
...
</pre>

<b>Detailed discussion:</b>

The script is executed by monit and the return value is used to decide 
the success. That is, if the script returns 0 it succeded and if it returns 
anything else it failed.

The new sub-statement [TIMEOUT AFTER X sec] is used to timeout execution. 
I.e if the script did not return after X seconds, monit aborts the execution
and the test failed. This statement is optional and if not used, defaults
to 5 seconds.

We should <i>not</i> use the popen(3) function. It is considered unsafe and 
is only a variant of the system(3) call. Instead we should do our own plumbing
and use fork(2), execv(3) and pipe(2) to read output from the script. 
The output will be logged if and only if an error occured and also sent
in any alert message.

</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>hauk</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="00FFCC" align=center>
<b><font color="#ffffff">40%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>HIGH</b></td>
</tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="03">Event traceback</a></h3>

      Refactor the internal message passing conducted inside validate.c
      to make code more flexible and to allow protocol routines to
      pass detailed error-messages upwards so they are part of
      the alert message. Having a kind of chained exception
      traceback would be nice. Something like,

      <pre>
      Event backtrace: 
      1. 'hostname' failed protocol test [http] at 192.168.1.1
      2. APACHE-STATUS error: 80 percent of Apache processes are logging
      </pre>

      Currently only the first event line (1.) are sent in the
      alert message. The error in line 2 is logged, but it could
      be nice to include it in the alert message to describe
      <i>why</i> the http protocol test failed.
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>MEDIUM</b></td>
  </tr>
</table>

<table id="feature">
<tr>
<td colspan=2 >
<h3><a name="34">Timeofday actions</a></h3>

Make it possible to decide monit's actions based on the time of day.

<p>Request: <i>For example I have a nightly script that runs and kicks CPU load up
high causing monit to alert, but since its expected between 02:00 and
02:10 it creates a false alert therefore I want to instruct monit not
to alert about CPU load between these times.</i>

<p>Suggested solution from Mike Jackson

<p><b>if timeofday 0400-0410 then {action}</b>

</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>hauk</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>MEDIUM</b></td>
</tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="06">URL request for protocol tests (like ldap, ftp, etc.)</a></h3>

      Add document request to relevant protocol tests. Currently
      only the http protocol test support a request option.

    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="07">Network interfaces health and load monitoring</a></h3>

      Allows to monitor network interfaces (for example "eth0" on linux,
      "hme0" on solaris, etc.) status - functionality and throughput. In the case
      that the interface will fail or the load exceeds some limit, monit
      will do appropriate action.
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="08">Filesystem load average tests</a></h3>

      Watch filesystem load:
      <p>
      - read/write blocks per second ratio<br>
      - transactions per second ratio<br>
      - queue lengths<br>
      - response times<br>
      </p>
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>Martin</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="09">Filesystem related caches test</a></h3>

      Watch cache hit ratio for inode, directory entry, buffer
      and similar caches.
   </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>Martin</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="10">IPv6 support</a></h3>

      Make monit speak Ipv6, both for network protocol
      test and in the built-in web server.
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="11">S.M.A.R.T capable devices monitoring support</a></h3>

      Support for monitoring health of devices which supports S.M.A.R.T
      technology. It allows you to watch for example disks and tape health,
      temperature, block realloacation, number of start count, power on hours,
      spin up time, etc. and allows you to detect bad device before
      catastrophic failure will occure.
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="18">ARP (MAC address) tests in host services</a></h3>
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>Christian</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="19">SCSI ping support for device test</a></h3>

      Allows to test whether the device is accessible. It is common
      test used by clusters for shared device (disk) based quorums
      (based on SCSI reservation).
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>Martin</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>


<table id="feature">
  <tr>
    <td colspan=2>
      <h3><a name="21">Action list support and optional service name target</a></h3>

      Allows to specify list of actions, optionaly referencing other
      service name in monit control file.<br>

      <p>
      Possible syntax (example):
      </p>

      <pre>
      IF FAILED test THEN {action [service], ...}
      </pre>

      <p>
      Example usage:
      </p>

      <pre>
      check process ipsec with pidfile /var/run/ipsec.pid
        start program = "/etc/init.d/ipsec start"
        stop program = "/etc/init.d/ipsec stop"

      check host theotherside with address the.other.side
        if failed icmp type echo then alert, restart ipsec
      </pre>
    </td>
  </tr>
  <tr>
    <td width="10%" style="padding-right: 20px;">Responsible:</td>
    <td>?</td>
  </tr>
  <tr>
    <td>Progress:</td>
    <td bgcolor="blue" align=center>
      <b><font color="#ffffff">0%</font></b>
    </td>
  </tr>
  <tr>
    <td>Importance:</td>
    <td><b>LOW</b></td>
  </tr>
</table>



<table id="feature">
<tr>
<td colspan=2>
<h3><a name="26">Support for status listing by service group</a></h3> 
The monit status and summary should support the group option for
restricting output to particular service group (currently status of
all services is listed regardless the group option).
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="27">Support for hard service dependency</a></h3> 
Monit currently supports the correct action sequence for dependency
chain, however it doesn't check whether the particular parent has
started and is running correctly before the child action is performed.
Hard dependencies support should be added to allow to wait for parent
to start and validate using the related testing rules that it is
available without errors before handling its dependants (and vice
versa in the case of stop action). This behavior could be optional, i.e.
hard (blocking) and soft (nonblocking) dependencies could be supported.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>Martin</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="28">Matching timeout rule should set the service state to 'timed out'</a></h3> 
The timeout rule currently sets the state to 'unmonitored' (besides
sending alarm), thus it is not possible to differentiate the reason
for which the service is unmonitored just in monit http interface nor
CLI (just the user who received alarm or who checks the monit logs
may know that the restart attempt ratio was too high). We should
mark the unmonitored-by-timeout state in http and CLI as well and
rather use red color in http then standard unmonitored yellow. The
state should be marked as 'timed out' or 'unmonitored by timeout'.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="29">Display filesystem type</a></h3> 
It could be good to display the filesystem type in Monit and M/Monit
http interface, such as ext3, hsfs, ntfs, ufs, etc.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="30">Log full start/stop/exec command</a></h3> 
It could be good to log full command as used during start, stop
program or exec action execution. Currently just the command itself
(argv[0]) is logged, for example when start program is defined as
'/etc/init.d/policyd start' then following message is logged on
start:
<pre>
Feb 7 07:26:29 somehost monit[321]: 'policyd' start: /etc/init.d/policyd
</pre>
instead of:
<pre>
Feb 7 07:26:29 somehost monit[321]: 'policyd' start: /etc/init.d/policyd start
</pre>
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>Martin</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="31">Add the MONIT_DESCRIPTION environment variable for exec</a></h3> 
It could be good to add the MONIT_DESCRIPTION environment variable when executing
the external programs (start/stop/exec). Currently there is MONIT_EVENT, but it
contains just the short event description.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td></td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="green" align=center>
<b><font color="#ffffff">100%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="36">Allow to override the implicit action on some events</a></h3> 
There are few internal events currently, which are not exposed for optional override:
<ul style="list-style-type: square;">
  <li>DATA</li>
  <li>EXEC</li>
  <li>INVALID</li>
  <li>NONEXIST</li>
  <li>TIMEOUT</li>
</ul>
The actions are initialized in the parser ... it could be good to allow the user to
change the default behavior when needed, as in the PID, PPID and FSFLAG case.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="38">Start/stop/exec method timeouts</a></h3> 
It could be good to add support for optional start/stop/exec methods timeout.
Currently monit waits for 1 cycle for service to start ... when the service
didn't recovered then this is handled as error. Some services however start
longer thus it could be useful to provide temporary "protection" to the method
to do its job.<br>
Example syntax:
<pre>
  start program = "/etc/init.d/httpd start" with timeout 3 cycles
</pre>
One cycle is default if the 'timeout' option is omitted (full backward
compatibility provided).
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>Martin</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="green" align=center>
<b><font color="#ffffff">100%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="39">Handle multiple lines matching the pattern in single MATCH statement as single group with one action</a></h3> 
Monit currently performs the action defined by the MATCH statement for each matching line immediately.
When multiple lines match in one cycle, monit thus performs the action multiple times.<br>
&nbsp;<br>
It could be good to optionally group the matching lines per one cycle and allow to perform
single/common action, since when monit is watching for example logfile, the burst of identical
messages can be found in one cycle, whereas they can be handled once (even one alert is enough
to know that the given event occured).<br>
&nbsp;<br>
Few ideas:<br>
&nbsp;<br>
1.) either perform the action on first match and suspend the given matching rule for the rest of the cycle.
    Advantage of this approach is that monit reaction to the event will be fast and the handling simple.
    Disadvantage is that when more complex matching rule is used, only the first match will be send
    as part of the alert and the other will be ignored, even though they may differ little bit (for
    example can contain the name of the failed device, etc.)<br>
&nbsp;<br>
2.) or evaluate the matching rules at the end of the input and buffer the matching lines. The advantage is,
    that all instances of lines matching even complex regex will be reported. Disadvantage is, that the
    reaction can be slower (suppose 100MB added to the file i.e. to process it will take some time), it can
    require more memory (when 100MB lines will match, then 100MB buffer will be needed unless some hardlimit
    will be used and even the user won't be most probably interested for 100MB mail). On the other side, such
    situations (extremely large data addition between monit cycles) may be rare and even this approach could
    work well for most setups. We can also improve it by adding just lines which differ to the buffer and
    report number of times the given message occured (although this reduces the disadvantage in most
    extreme ciscumstances with multiple same lines, when each line is different little bit the problem
    still exist).<br>
&nbsp;<br>
Syntax proposal:<br>
----------------<br>
&nbsp;<br>
IF MATCH [FIRST] {regex|path} THEN &lt;action&gt;<br>
<i>the FIRST is new option, which makes the MATCH rule act on first matching occurence</i><br>
&nbsp;<br>
IF MATCH [GROUP [LIMIT &lt;x&gt;]] {regex|path} THEN &lt;action&gt;<br>
<i>the GROUP is new option, which makes the MATCH rule act on first matching occurence</i><br>
&nbsp;<br>
<i>the LIMIT is another new extra option, which allows to limit the number of lines per group, thus reducing the memory footprint and size of alert body. The reaction can still be slow if lot of data were added - even if two instances (GROUP MAX 2) will be defined, the delta between instances may be large or there could be even just one matching line.</i><br>
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="40">Add the start/stop/restart throttling</a></h3> 
It could be good to support start throttling to control the
startup parallelism. Some servies (such as zope) may be configured
as many standalone instances, whereas the startup may create burst
in the system resources when they all start in parallel. We can
combine this with the service groups, so the user will for example
configure the limit to start at maximum two services from the group
per cycle.
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="41">Log the start/stop/exec program output</a></h3> 
It could be useful if we can catch the output from the start/stop/exec
script and optionally log it and/or add it to the start-failed event's
error message, so the user can figure out directly why the script
failed.

Currently monit logs:
<pre>
Mar 26 20:58:14 localhost monit[24709]: 'testapp_mongrel_1' trying to restart
Mar 26 20:58:14 localhost monit[24709]: 'testapp_mongrel_1' start: /usr/bin/mongrel_rails
Mar 26 20:58:44 localhost monit[24709]: 'testapp_mongrel_1' failed to start
</pre>

Whereas the script says more about the reason:
<pre>
starting port 10001
 !!! Prefix must begin with / and not end in /
 !!! User does not exist: Rtestapp
 !!! Group does not exist: Rtestapp
 mongrel::start reported an error. Use mongrel_rails mongrel::start -h to get help.
</pre>
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<table id="feature">
<tr>
<td colspan=2>
<h3><a name="42">Support timestamp test relative to other file</a></h3>
Feature for timestamp test for comparing file ages, such as "older than"
and "newer than". Example:

<pre>
 if timestamp /etc/aliases newer than /etc/aliases.db
    then /sbin/newaliases
</pre>

</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>



<table id="feature">
<tr>
<td colspan=2>
<h3><a name="43">Watch process' filedecriptors count</a></h3>
Possibility to monitor process' filedescriptor count ... every
OS usually has per-process soft and hard limits and if the process
exceeds the quota, there can be problems. If monit will be able
to watch filedescriptors, it can prevent the problem (either report
or automatically fix).
</td>
</tr>
<tr>
<td width="10%" style="padding-right: 20px;">Responsible:</td>
<td>?</td>
</tr>
<tr>
<td>Progress:</td>
<td bgcolor="blue" align=center>
<b><font color="#ffffff">0%</font></b>
</td>
</tr>
<tr>
<td>Importance:</td>
<td><b>LOW</b></td>
</tr>
</table>


<?php include '../include/footer.html'; ?>
