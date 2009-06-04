<?php include 'include/header.html'; ?>

<!-- Section header -->
      <center>
	<div class=headline>
<strong>New release:</strong> monit 5.0_beta4 is released. <a href=dist/beta/>Download here</a><br>
	</div>
	<table width="680"><tr> <td><a href="growl.wav"><img
	src="img/monit.gif" border=0></a></td>
	    </tr>
	</table>
      </center>
    <br><p>

<?php include 'include/menu.php'; ?>

      <table border="0" cellpadding="0" cellspacing="0" id="content">
	<tbody>
	  <tr>
	    <td style="vertical-align: top;" >
	      
	      <b>monit is a utility for managing and monitoring,
	      processes, files, directories and filesystems on a UNIX
	      system. Monit conducts <i>automatic maintenance and
	      repair and can execute meaningful causal actions</i> in
	      error situations.</b> 
	      
	     <br><p><img src="img/features.gif" align=right border=0
	     style='padding: 0px 0px 0px 10px'><b>What monit can
	     do</b><br> Monit can start a process if it does not run,
	     restart a process if it does not respond and stop a
	     process if it uses too much resources. You can use monit
	     to monitor files, directories and filesystems for changes,
	     such as timestamp changes, checksum changes or size
	     changes. You can also monitor remote hosts; monit can
	     ping a remote host and can check TCP/IP port connections
	     and server protocols. Monit is controlled via an easy to
	     use control file based on a free-format,
	     token-oriented syntax. Monit logs to syslog or to its own
	     log file and notifies you about error conditions and
	     recovery status via customizable alert. 

	     <br><p><img src="img/design.jpg" align=left border=0
	     style='padding: 10px 10px 0px 0px'><b>Design
	     philosophy</b><br>It is important for a system monitoring
	     tool to <i>just work</i> - all the time and you should be able to
	     trust it to do so. A system monitoring tool need to be
	     non-intrusive and you should be able to forget about it
	     once it's installed. That is, until
	     <code>sshd</code> dies on your co-located server, 50
	     miles away. When this happens, it is good to know that
	     you have installed this extra layer of security and
	     protection - just wait a few seconds and monit will
	     restart the <code>sshd</code> daemon. It is also helpful
	     to get an alert mail before the server disks are full
	     or if your http server suddenly is <a
	     href="http://en.wikipedia.org/wiki/Slashdotted">slashdotted</a>.

	     <br><p>Monit is designed as an autonomous system and does
	     not depend on plugins nor any special libraries to
	     run. Instead it works right out of the box and can
	     utilize existing infrastructure already on your
	     system. For instance, monit will easily integrate with
	     <code>init</code> and can use existing runlevel
	     <code>rc-scripts</code> to manage services. There are also
	     flexibility for those special cases when you need a
	     certain setup for a service. 

             <br><p> Monit compiles and run on most flavors of
             UNIX. It is a small program and weights in at just over
             300kB. There is support for compiling with
             <code>glibc</code> replacements such as <a
             href="http://www.uclibc.org/">uClibc</a> if you need it
             to be even smaller.


             <br><p><a href="doc/screen.php"><img
             src="img/t_monit_httpd.png" align=right border=0
             style='padding: 10px 10px 0px 0px'></a> <b>Check server
             status with a Web Browser</b><br>Monit provides a
             built-in HTTP(S) interface and you can use a browser to
             access the monit server. Check out the <a
             href="doc/screen.php">screen shoots page</a> for an
             overview of available pages. Status is also provided in
             XML. This makes it easy to integrate monit with other
             tools or for providing alternative output formats.  For
             example, a PHP wrapper script is available for viewing
             the server status on a WAP phone.


             <br><p><a href="doc/monit.pdf"><img
             src="img/getstarted.gif" align=left border=0
             style='padding: 10px 0px 0px 0px'></a><b>Getting
             started</b><br> Read the <a href="doc/monit.pdf">monit
             presentation</a>, available in PDF. Browse the <a
             href="doc/manual.php">monit manual</a> online.<br>

	     <br><p><b><a href="http://opensource.org/"><img
	     src="img/osi-certified-90x75.gif" align=right border=0
	     style='padding: 10px 10px 0px 0px'></a>Open source
	     </b><br> Monit is free software; you can redistribute it
	     and/or modify it under the terms of the <a
	     href="http://www.gnu.org/licenses/gpl.html">GNU General
	     Public License</a>. Monit is an open-source project
	     consisting of non-paid volunteers who contribute work and
	     code to the project in their own free time. The project
	     consists of a core team of developers and many
	     contributors from around the world. There is also a large
	     and active community of users who discuss usage of monit,
	     answer questions and share tips and hacks on the monit
	     mailing lists.

         <br><p><b><a
         href="http://savannah.nongnu.org/mail/?group=monit"><img
         src="img/mail.jpg" align=left border=0 style='padding:
         10px 10px 0px 0px'></a>Mailing lists</b><br>We have setup
         a mailing list which contain many individuals who will
         help answer detailed requests for help. You may also
         search the <a
         href="http://lists.gnu.org/archive/html/monit-general/">archive</a>
         for answers. Join the <a
         href="http://lists.nongnu.org/mailman/listinfo/monit-general">monit
         general list</a> if you have questions or if you simply
         want to discuss monit and submit ideas, suggestions, and
         comments. New releases will also be announced to this
         list. Join the <a
         href="http://lists.nongnu.org/mailman/listinfo/monit-dev">monit
         developer list</a> if you want to discuss design issues,
         code changes, additions, etc.
         <p>If you only want to get a notification when new releases
	     of monit are available, please join the very low traffic
         <a href="http://lists.nongnu.org/mailman/listinfo/monit-announce">monit
         announce mailing list</a>. This list is used to announce 
         major releases and other important information about the monit 
         project. Messages are posted only by the monit project; there 
         is no discussion.
    	     
	     <br><p><b><a href="donate.php"><img src="img/20euro.jpg"
	     align=right border=0 style='padding: 10px 10px 0px
	     0px'></a>Support monit</b><br>Any donation is greatly
	     appreciated and will help us continue to develop and
	     support Monit. When you <a href="donate.php">donate
	     money</a> or support us by other means you will be
	     mentioned under the <a href="sponsors.php">sponsors
	     section</a> on the monit web site (unless you want to be
	     anonymous). Feature requests backed up by a donation is
	     also much more likely to be prioritized compared with
	     other requests.
	

	     <br><br><p><b><a href="http://www.fsf.org/"><img
	     src="img/gnu.jpg" align=left border=0 style='padding:
	     10px 0px 0px 0px'></a>Acknowledgments</b><br> Thanks to
	     the <a href="http://www.fsf.org/">Free Software
	     Foundation (FSF)</a> for hosting the CVS repository and
	     the mailing lists.



	    </td>
	  </tr>
      </table>

<?php include 'include/footer.html'; ?>
