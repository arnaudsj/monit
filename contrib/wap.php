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
//  -----------------------------------------------------------------------
//
//  DESCRIPTION
//  Script to display basic monit status information in WML on a WAP phone.
//  Based on the contrib/monit.php script for remote access to monit, 
//  and including some XML functions developed by 
//  mreilly at ZEROSPAM dot MAC dot COM taken from the PHP manual.
//  
//  INSTALLATION
//  Place this script on your webserver. Set the configuration information 
//  to match your monit installation. The password can be included in the
//  page request, in which case set it as an empty string in this script.
//  
//  Use this type of request from your phone (with your password!):
//  http://  www.example.co.uk/wap.php?pass=monit 
//  
//  Bookmark this if you are happy that your phone is secure.
//  
//  This script accesses monit from the localhost, so you don't
//  need to allow external access to monit through your firewall, 
//  just access your normal webserver.
//  
//  Much of the XML manipulation would be better done using Extensible
//  Stylesheet Language (XSL) Transformations, but they need additional
//  libraries which not everyone has installed.
//  
//  This script only outputs basic data, but the array generated from the
//  XML status information holds everything in the monit status report. 
//  Just add additional output echo statements to get more detail.
//  
//  This script requires PHP, and a working webserver! Tested on PHP4.
//
//  @author Author David Fletcher, <david@megapico.co.uk>

//Configuration data
$addr = 'localhost';
$port = 2812;
$path = '/_status?format=xml';
$user = 'admin';
$pass = '';
$timeout = 30;
//End of configuration

//Ensure that the page generated appears to be a WML page.
header("Content-type: text/vnd.wap.wml");

//No security or filtering here.
//Passwords could contain almost anything, so difficult to filter
if(isset($_GET['pass'])) $pass = $_GET['pass'];

//Get the status information from monit
$urlHandle = fsockopen($addr, $port, $errno, $errstr, $timeout);
socket_set_timeout($urlHandle, $timeout);

$urlString = "GET $path HTTP/1.0\r\nHost: $addr\r\nConnection: Keep-Alive\r\nUser-Agent: MonitPHP\r\n";
$urlString .= "Authorization: Basic ".base64_encode("$user:$pass")."\r\n";
$urlString .= "\r\n";

fputs($urlHandle, $urlString);
$response = fgets($urlHandle);

$endHeader = false;                         // Strip initial header information
while ( !$endHeader){
  if (fgets($urlHandle) == "\r\n")
    $endHeader = true;
}

$data = '';                          // Generate a string to send to the screen

while (!feof($urlHandle)) {
  $data.=fgets($urlHandle);
}

fclose ($urlHandle);

//Status information is now stored as an XML document as $data
//Convert the XML to an array to make output controllable

// Array to store current xml path
$ary_path = array();

// We may have many services. They need to be numbered to keep track
$service_no = 0;

// Array to store parsed data
$data_parsed = array();

// Starting level - Set to 0 to display all levels. Set to 1 or higher
// to skip a level that is common to all the fields.
$int_starting_level = 1;

// create our parser
$xml_parser = xml_parser_create('UTF-8');

// set some parser options
xml_parser_set_option($xml_parser, XML_OPTION_CASE_FOLDING, true);
xml_parser_set_option($xml_parser, XML_OPTION_TARGET_ENCODING, 'UTF-8');

// tell PHP what functions to call when it finds an element
xml_set_element_handler($xml_parser, 'startElement','endElement');

// tell PHP what function to use on the character data
xml_set_character_data_handler($xml_parser, 'characterData');

//Parse the XML
if (!xml_parse($xml_parser, $data)) {
  die(sprintf( "XML error: %s at line %d\n\n", 
	       xml_error_string(xml_get_error_code($xml_parser)),
	       xml_get_current_line_number($xml_parser)));
}

xml_parser_free($xml_parser);

// This function is called for every opening XML tag. We
// need to keep track of our path in the XML file, so we
// will use this function to add the tag name to an array
function startElement($parser, $name, $attrs=''){

  // Make sure we can access the path array
  global $ary_path,$service_no;

  //Service type 5 is system information, not a standard service
  if(isset($attrs['TYPE']) && $attrs['TYPE'] == 5){
    $name = 'SYSTEM';
  }

  // Push the tag into the array
  array_push($ary_path, $name);

  //If the tag is a new SERVICE, increment the number of services
  if($name == 'SERVICE'){
    $service_no++;
  }

}

// This function is called for every closing XML tag. We
// need to keep track of our path in the XML file, so we
// will use this function to remove the last item of the array.
function endElement($parser, $name, $attrs=''){

  // Make sure we can access the path array
  global $ary_path;

  // Push the tag into the array
  array_pop($ary_path);

}

// This function is called for every data portion found between
// opening and closing tags. We will use it to insert values
// into the array.
function characterData($parser, $data){

  // Make sure we can access the path and parsed file arrays
  // and the starting level value
  global $data_parsed, $ary_path, $int_starting_level, $service_no;

  // Remove extra white space from the data (so we can tell if it's empty)
  $str_trimmed_data = trim($data);

  // Since this function gets called whether there is text data or not,
  // we need to prevent it from being called when there is no text data
  // or it overwrites previous legitimate data.
  // Don't use !empty since it will miss tags which contain the number zero.
  if ($str_trimmed_data != '') {

    // Build the array definition string
    $str_array_define = '$data_parsed';

    // Add a [''] and data for each level. (Starting level can be defined.)
    for ($i = $int_starting_level; $i < count($ary_path); $i++) {
      if ($ary_path[$i] == 'SERVICE'){
	//Several SERVICE entries must be accommodated.
	$ary_path[$i] = $ary_path[$i].'-'.$service_no;
      }
      $str_array_define .= '[\'' . $ary_path[$i] . '\']';  
    }

    // Add the value portion of the statement
    $str_array_define .= " = '" . $str_trimmed_data . "';";

    // Evaluate the statement we just created
    eval($str_array_define);

  } // if

}

//Prepare for output of the most basic monit data

//For conversion of status codes to text
$event[0] = 'OK';
$event[1] = 'Checksum failed';
$event[2] = 'Resource limit matched';
$event[4] = 'Timeout';
$event[8] = 'Timestamp failed';
$event[16] = 'Size failed';
$event[32] = 'Connection failed';
$event[64] = 'Permission failed';
$event[128] = 'UID failed';
$event[256] = 'GID failed';
$event[512] = 'Does not exist';
$event[1024] = 'Invalid type';
$event[2048] = 'Data access error';
$event[4096] = 'Execution failed';
$event[8192] = 'Changed';
$event[16384] = 'ICMP failed';

$monitored[0] = 'No';
$monitored[1] = 'Yes';
$monitored[2] = 'Init';

//Output document headers. Note that the blank lines between DOCTYPE and <wml> are important.
echo '<?xml version="1.0"?>';
echo '<!DOCTYPE wml PUBLIC "-//WAPFORUM//DTD WML 1.1//EN" ';
echo '"http://www.wapforum.org/DTD/wml_1.1.xml">';
echo "\n\n";
echo '<wml><head><meta http-equiv="Cache-Control" content="no-cache,must-revalidate"/>';
echo '<meta http-equiv="Pragma" content="no-cache"/></head><template>';
echo '<do type="prev" label="Back"><prev/></do></template><card id="main" title="Server status">';

//Do outputs linked to the machine, not to a specific service

echo '<p>'.date('H:i j-M-y').'</p>';
echo '<p><b>Hostname</b>: '.$data_parsed['SYSTEM']['NAME'].'<br />';

$days = floor($data_parsed['SERVER']['UPTIME']/60/60/24);
$hours = $data_parsed['SERVER']['UPTIME']/60/60%24;
$mins = $data_parsed['SERVER']['UPTIME']/60%60;

echo 'Uptime: '.$days.'d '.$hours.'h '.$mins.'m<br />';
echo 'Load: '.$data_parsed['SYSTEM']['LOAD']['AVG15'].'<br />';
echo 'Memory: '.$data_parsed['SYSTEM']['MEMORY']['PERCENT'].'%<br />';
echo 'User cpu: '.$data_parsed['SYSTEM']['CPU']['USER'].'%<br />';
echo 'System cpu: '.$data_parsed['SYSTEM']['CPU']['SYSTEM'].'%</p>';

//Output for each of the services monitored

for ($i = 1; $i <= $service_no; $i++){

  echo '<p>';
  //Service name
  echo '<b>'.$data_parsed["SERVICE-$i"]['NAME'].'</b><br />';

  //Is this service being monitored?
  if(array_key_exists($data_parsed["SERVICE-$i"]['MONITOR'], $monitored))
    echo 'Monitored: '.$monitored[$data_parsed["SERVICE-$i"]['MONITOR']].'<br />';
  else
    echo 'Monitored: '.$data_parsed["SERVICE-$i"]['MONITOR'].'<br />';

  //What is the status of this service?
  if(array_key_exists($data_parsed["SERVICE-$i"]['STATUS'], $event))
    echo 'Status: '.$event[$data_parsed["SERVICE-$i"]['STATUS']].'<br />';
  else
    echo 'Status: '.$data_parsed["SERVICE-$i"]['STATUS'].'<br />';

  //If this service defined an UPTIME, display it.
  if(isset($data_parsed["SERVICE-$i"]['UPTIME'])){
    $days = floor($data_parsed["SERVICE-$i"]['UPTIME']/60/60/24);
    $hours = $data_parsed["SERVICE-$i"]['UPTIME']/60/60%24;
    $mins = $data_parsed["SERVICE-$i"]['UPTIME']/60%60;
    echo 'Uptime: '.$days.'d '.$hours.'h '.$mins.'m<br />';
  }

  echo '</p>';  
}

echo '</card></wml>';

?>

