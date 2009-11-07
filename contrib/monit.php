<?php
//  Copyright (C), 2004 David Fletcher, <david@megapico.co.uk>
// 
//  This program is free software; you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as
//  published by the Free Software Foundation; either version 3 of the
//  License, or (at your option) any later version.
// 
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software Foundation,
//  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//  
//  DESCRIPTON
//  Script to forward a request on a web server to the Monit webserver.
//  Allows the Monit information screen to be viewed remotely, without 
//  leaving an additional port open on the server.
//
//  INSTALLATION
//  Place this script on your webserver.
//  Use a password protected area if you like.
//  Set the configuration information below to match your monit installation. 
//  With this script you are accessing monit from the localhost, so you don't
//  need to allow external access through your firewall.
//
//  Requires PHP, and a working webserver!
//  @author Author David Fletcher, <david@megapico.co.uk>


//Configuration - set this to match the information in /etc/monitrc
//Set information about the monit server address, port and login details.
$addr = 'localhost';
$port = 2812;
$path = '/';
$user = 'admin';
$pass = 'monit';
$timeout = 30;
//End of configuration

$urlHandle = fsockopen($addr, $port, $errno, $errstr, $timeout);
socket_set_timeout($urlHandle, $timeout);

$urlString = "GET $path HTTP/1.0\r\nHost: $addr\r\nConnection: Keep-Alive\r\nUser-Agent: MonitPHP\r\n";
$urlString .= "Authorization: Basic ".base64_encode("$user:$pass")."\r\n";
$urlString .= "\r\n";
      
fputs($urlHandle, $urlString);
$response = fgets($urlHandle);

$endHeader = false;                           // Strip initial header information
while ( !$endHeader){
  if (fgets($urlHandle) == "\r\n")
    $endHeader = true;
}

$info = '';                                  // Generate a string to send to the screen

while (!feof($urlHandle)) {
  $info.=fgets($urlHandle);
}

fclose ($urlHandle);

echo $info;

?>
