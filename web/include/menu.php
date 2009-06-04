<?php 
  function isSelected($U, $N)
  {
    $uri= $_SERVER['REQUEST_URI']; 
    if(strpos($uri, $U)!==false) {
      print "<td nowrap class='selected'><a class='selected' href='$U'>$N</a></td>";
    } else {
      print "<td nowrap><a href='$U'>$N</a></td>";
    }
  }
?>
<center>
  <table width="700" border="0" cellpadding="0" cellspacing="0" id="nav">
    <tr align="left" valign="middle">
    <?php isSelected("/monit/news/", "News"); ?>
    <?php isSelected("/monit/doc/", "Documentation"); ?>
    <?php isSelected("/monit/download/", "Download"); ?>
    <?php isSelected("/monit/story/", "User Stories"); ?>
    <?php isSelected("/monit/support/", "Support & Services"); ?>
    <?php isSelected("/monit/who.php", "Who We Are"); ?>
    <?php isSelected("/monit/sponsors.php", "Sponsors"); ?>
    </tr>
  </table>
</center>

