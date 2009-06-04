<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

<h2>Install instructions</h2>

<ul style="list-style-type: square">

<li>Download the latest monit release from <a
href="/monit/download/">the download area</a> <br><p>

<li><b>Installing monit</b>: <ul style="list-style-type:
none"><li><code>$ tar zxvf monit-x.y.z.tar.gz</code> (x.y.z denotes
version numbers, for instance; monit-4.5.1.tar.gz) <li><code>$ cd
monit-x.y.z</code> <li>$ <code>./configure</code> (use ./configure
--help to view available options) <li><code>$ make &amp;&amp; make
install</code></ul>
</ul>

By default monit is installed in <code>/usr/local/bin/</code> and the
monit.1 man-file in <code>/usr/local/man/man1/</code>. To change the
default location use the <code>--prefix</code> option to
<code>./configure</code>

<h3>Problems?</h3>

If you have questions or comments about the software or documentation
please subscribe to the <a
href="http://mail.freesoftware.fsf.org/mailman/listinfo/monit-general">monit
general mailing list</a>. You can also look in the <a
href="http://mail.freesoftware.fsf.org/pipermail/monit-general/">mailing
list archive</a> for answers



<?php include '../include/footer.html'; ?>
