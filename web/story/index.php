<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

We need your story here! Send an email to <font
color=blue>&#109;&#111;&#110;&#105;&#116;&#103;&#114;&#111;&#117;&#112;&#064;&#116;&#105;&#108;&#100;&#101;&#115;&#108;&#97;&#115;&#104;&#046;&#99;&#111;&#109;</font>
with your story. Maybe you can submit a
picture of yourself and/or your machines running monit? The story does not have to be
long, one or two paragraphs are fine. A one-liner is also okay.<br>

<p>
  Stories:<br>

  <ul style="list-style-type: square;">
    <li><a href="#labahn">Dietmar Labahn</a>
    <li><a href="#sturtewagen">Tim Sturtewagen</a>
    <li><a href="#methke01">methke01</a>
  </ul>
</p>

<div style="background: #f0f0f0; padding: 0px 0px 2px 10px; border: 1px dotted #ccc;">
<a name="labahn"></a>
<p>
<i>Contributed by Dietmar Labahn</i>
</p>
<p>
I use Linux CUPS and LPRng Print- and workflow servers. Because these
servers are essential to the company (Automotive), I decided to implement a
Heartbeat solution. During the print process the invoices are also
transfered to a document management system (EASY), we convert the printfiles
as well to PDF and create index files for the DMS. In addition, we send
certain printfiles to certain people as PDF mail attachments.
</p>
<p>
It is clear that it would cost the company a lot of money, if the system
would fail. I decided to use the HA system in connection with monit. Two
Intel-based servers (Raid 5) running under SUSE LINUX 8.2 with mostly
redundant hardware is the platform.
</p>
<p>
Heartbeat and monit are configured as suggested under the monit website,
which means that monit is started by the system daemon (configured via
inittab). It then starts Heartbeat, via its configuration file monitrc, by
the monit option "start group local". This means, when coming up, monit
starts all services marked as local. The services CUPS, postfix and Samba
are started by Heartbeat, using the monit "Start Group" option. This means
that the services are under control of both HA and monit. HA takes care that
the services are only running on the active node, and monit takes care that
they are monitored and restarted on the active node if needed. Because the
main server is changed now and then (printers added, deleted, configuration
files changed etc), I use CRON and scripts to update the backup server with
all the relevant files once a day (at night).</p>
<p>
Until now, it has worked like a charm (even though no failures happened
yet). From my point of view, I can recommend it highly. It takes some time
to get to all the bits, but then ..... On the other hand -- who ever said
that such a highly sofisticated system is trivial. I am now at my 4th HA
installation, and it works perfectly! 
</p>
</div>
<div style="background: #fff; padding: 0px 0px 2px 10px; border: 1px dotted #ccc;">
<a name="sturtewagen"></a>
<p>I have only last week installed monit on a machine we use for tomcat application serving. Our company is in the process of upgrading the server, but needed a monitoring application for the time being to make sure the tomcat server doesn't go down every week or two. Our ISP (<a href="http://www.positive-internet.com">www.positive-internet.com</a>) advised us to try out monit;
<p><code>"My advice would be to use something like monit. You can install it via Debian (apt-get install monit). It's a wonderful bit of software.
...
Spend an hour or so looking at the config examples, and then another setting up your machine just so means that you can get it running like clockwork."</code>

<p>So I did! It took me some more time - I had some calls and other stuff in between - but after a few hours, monit was up and running on Thursday afternoon.

<p>I only installed one configuration, for checking the tomcat process over a http connection. In case of no response, monit would restart the tomcat app server. As alert address I entered my i-mode email address, so that any email would arrive on my mobile phone [I live in Brussels and use <a href="http://www.base.be">www.base.be</a>].
        
<p>On Friday night I left for Madrid, as I was going to a wedding party on Sunday afternoon [in Madrid I automatically roamed on <a href="http://www.amena.com/">www.amena.com</a>].
                
<p>Quiet weekend, nice wheather, cool city and then ... it is Sunday morning. Me and my girlfriend are getting ready to go to the party, we still have one hour before we have to leave. Suddenly an email arrives on my phone. It was monit, telling me the tomcat protocol test had failed.
                
<p>Damn!
               
<p>It was 35 degrees outside, and I was sweating like hell. I didn't really have the time to sort out what was happening. There was a computer running in the very room I was in, so I looked up the server, and indeed it was down, showing me the horrible "Internal Server Error". At the same moment a second mail arrived. Monit again. The tomcat4 process had died.
                
<p>There was no ssh client on the computer I was using, so I quickly downloaded putty. Before I had opened it, a third mail arrived. More bad news from monit, I thought. But no, this was a happy message. My faithful employee was sending me tomcat's new pid id! And another mail came in. Now telling me the tomcat connection had succeeded.
                
<p>I reloaded the browser window, and yes, all was up again! In only 6 minutes, monit had handled the situation and kindly told me what it was doing in the meantime. Wonderful.
                
<p>Many thanks and kind regards,

<p>Tim Sturtewagen

<p><i>Doggybites BVBA</i>
                
</div>

<div style="background: #f0f0f0; padding: 0px 0px 2px 10px; border: 1px dotted #ccc;">
<a name="methke01"></a>
<p>
<i>Contributed by methke01</i>
</p>
<p>
Hi there, 
</p>
<p>
I was quite nervous, registered for some shops, mailing lists and things like that but never got mails in reply. After 4 days being not reachable and searching for the reason I found a changed library, postfix linked to it and down for nearly a week. I already use a small SVG-perl script to render the system's temperature to my homepage, but that does not show if a certain process fails or is not up and running.
</p>
<p>
After crawling through gentoo's repository I found the only one package to solve my problems and finally emerged monit. It did not run out of the box, the page was empty and most of the listed examples had to be edited. But within 15 minutes I had a full setup, full service and only green status messages.
</p>
<p>
Additionally you receive my configuration, added postgresql-service and apache2, vixie-cron, vsftp and slapd/openldap, all in gentoo-layout.
</p>
<p>
Thanks for the small but useful package, Greetings from Germany 
</p>
</div>

<?php include '../include/footer.html'; ?>
