/*
 * Copyright (C) 2011 Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */


#ifndef CERVLET_H
#define CERVLET_H

#include <config.h>

#include "monitor.h"

#define HEAD_HTML \
"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">"\
"<html>"\
"<head>"\
"  <title>%s Monit</title>"\
"  <style type=\"text/css\">"\
"  body {"\
"	margin: 0;"\
"  }"\
"  body, p, div, td, th, tr, form, ol, ul, li, input, textarea, select, a {"\
"  	font-family: \"lucida grande\", verdana, geneva, arial, helvetica, sans-serif;"\
"  	font-size: 14px; "\
"  }"\
"  a:hover {"\
"  	text-decoration: none;"\
"  }"\
"  a  {"\
"  	text-decoration: underline;"\
"  }"\
"  .foot {"\
"        padding-top:40px;"\
"        font-size:10px;"\
"        color: #333333;"\
"  } "\
"  .foot a {"\
"        font-size:10px;"\
"        color: #000000;"\
"  } "\
"  </style>"\
"<meta HTTP-EQUIV=\"REFRESH\" CONTENT=%d>"\
"<meta HTTP-EQUIV=\"Expires\" Content=0>"\
"<meta HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">"\
"</head>"\
"<body bgcolor=\"#ffffff\" link=\"#000000\" vlink=\"#000000\""\
" alink=\"#000000\" text=\"#000000\">"\
"<table cellspacing=\"0\" cellpadding=\"0\" width=\"100%%\" border=\"0\">"\
" <tr bgcolor=\"#6F6F6F\">"\
"  <td valign=\"bottom\"><img src=\"_pixel\" width=\"1\" height=\"1\" alt=\"\"></td>"\
"  </tr>"\
"</table>"\
"<table cellspacing=\"0\" cellpadding=\"10\" width=\"100%%\" border=\"0\">"\
"  <tr bgcolor=\"#DDDDDD\">"\
"    <td align=\"left\" valign=\"top\" width=\"20%%\" bgcolor=\"#DDDDDD\"><font color=\"#000000\"><small><a href='.'>Home</a>&gt;<a href='%s'>%s</a></small></font></td>"\
"    <td align=\"center\" valign=\"top\" width=\"60%%\" bgcolor=\"#DDDDDD\" style=\"font-size:12px; color:#555;\">Use <a href='http://mmonit.com/' style=\"font-size:12px;\">M/Monit</a> to manage all your Monit instances</td>"\
"    <td align=\"left\" valign=\"top\" width=\"20%%\" bgcolor=\"#DDDDDD\"><p align=\"right\"><small><a href='_about'>monit " VERSION "</a></small></td>"\
"  </tr>"\
"</table>"\
"<table cellspacing=\"0\" cellpadding=\"0\" width=\"100%%\" border=\"0\">"\
"  <tr bgcolor=\"#6F6F6F\">"\
"    <td><img src=\"_pixel\" width=\"1\" height=\"1\" alt=\"\"></td>"\
"  </tr>"\
"</table>"\
"<center>"


#define FOOT_HTML "</center>"\
"<div align=\"center\" class=\"foot\" style=\"margin:20px auto\">"\
"Copyright &copy; 2000-2011 <a href=\"http://tildeslash.com/\">Tildeslash</a>. All rights reserved. "\
"<span style='margin-left:5px;'></span>"\
"<a href=\"http://mmonit.com/monit/\">Monit web site</a> | "\
"<a href=\"http://mmonit.com/wiki/\">Monit Wiki</a> | "\
"<a href=\"http://mmonit.com/\">M/Monit</a>"\
"</div></body></html>"


#define HEAD(path, name, refresh) \
   out_print(res, HEAD_HTML, Run.localhostname, refresh, path, name);

#define FOOT  out_print(res, FOOT_HTML);


#define PIXEL_GIF "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="


/* Public prototypes */
void init_service();

#endif
