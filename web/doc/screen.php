<?php include '../include/header.html'; ?>

<center>
<table width="680"><tr> <td><img src="index.gif"></td></tr></table>
</center>

<?php include '../include/menu.php'; ?>

<h2>Screen shoots</h2>


<table border="0" cellpadding=5 cellspacing=10 id="content">
    <tr>
    <td>
      <a href="shoots/monit47_httpd.png"><img
        src="shoots/t_monit47_httpd.png" align=left border=0></a>
    </td>
    <td>
    This is the main page displayed when you access the monit daemon
    from a browser. This page shows an overview and the status for all
    services monitored. Clicking on a service link will show more
    detailed information. Another <a href="shoots/monit_httpd.gif">
    example</a> demonstrating various status
    
    </td>
    </tr>
    <tr>
    <td>
      <a href="shoots/monit-44.png"><img
      src="shoots/t_monit-44.jpg" align=left border=0></a>
    </td>
    <td>
    This screen shoot demonstrate how the main page may look like if
    you take your monitoring business serious.
    </td>
    </tr>

    <tr>
    <td>
      <a href="shoots/monit_httpd1.png"><img
      src="shoots/t_monit_httpd1.png" align=left border=0></a>
    </td>
    <td>
    This page is displayed when you click on a service link. Detailed
    service information are available, but more important; from this
    page you can start, stop and restart the service and also
    enable/disable monitoring.
    </td>
    </tr>

    <tr>
    <td>
    <a href="shoots/monit_httpd2.gif"><img src="shoots/t_monit_httpd2.jpeg"
    align=left border=0></a>
    </td>
    <td>
    The runtime page shows information about the monit daemon. If you
    have setup monit to log to its own log file you can also view the
    content of the log file. From this page it is possible to stop the
    monit http server thread, <i>without</i> stopping the monit
    daemon.
    </td>
    </tr>

    <tr>
    <td>
    <a href="shoots/console1.gif"><img src="shoots/t_console1.jpg"
    align=left border=0></a>
    </td>
    <td>
    If a monit daemon was started with http support (strongly
    recommended) you can then view detailed service information from
    the console. From the console you can also start, stop and restart
    services.
    </td>
    </tr>

    <tr>
    <td>
    <a href="shoots/alert1.gif"><img src="shoots/t_alert1.jpeg" align=left
    border=0></a>
    </td>
    <td>
    Monit will raise alert messages when error events occurs. Here, a
    standard error message is viewed.
    </td>
    </tr>
   
   </table>


<?php include '../include/footer.html'; ?>
