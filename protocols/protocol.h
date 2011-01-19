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


#ifndef MONIT_PROTOCOL_H
#define MONIT_PROTOCOL_H

#include <config.h>

#include "monitor.h"
#include "socket.h"

/* Protocols supported */
#define P_DEFAULT         1
#define P_HTTP            2
#define P_FTP             3
#define P_SMTP            4
#define P_POP             5
#define P_IMAP            6
#define P_NNTP            7
#define P_SSH             8
#define P_DWP             9
#define P_LDAP2          10
#define P_LDAP3          11
#define P_RDATE          12
#define P_RSYNC          13
#define P_GENERIC        14
#define P_APACHESTATUS   15
#define P_NTP3           16
#define P_MYSQL          17
#define P_DNS            18
#define P_POSTFIXPOLICY  19
#define P_TNS            20
#define P_PGSQL          21
#define P_CLAMAV         22
#define P_SIP            23
#define P_LMTP           24
#define P_GPS            25
#define P_RADIUS         26
#define P_MEMCACHE       27

void  gc_protocols();

/* Protocol Factory routines */
void* create_apache_status();
void* create_default();
void* create_dns();
void* create_dwp();
void* create_ftp();
void* create_generic();
void* create_http();
void* create_imap();
void* create_clamav();
void* create_ldap2();
void* create_ldap3();
void* create_mysql();
void* create_nntp();
void* create_ntp3();
void* create_postfix_policy();
void* create_pop();
void* create_smtp();
void* create_ssh();
void* create_rdate();
void* create_rsync();
void* create_tns();
void* create_pgsql();
void* create_sip();
void* create_lmtp();
void* create_gps();
void* create_radius();
void* create_memcache();

/* "Package" locale Protocol routines */
int check_apache_status(Socket_T);
int check_default(Socket_T);
int check_dns(Socket_T);
int check_dwp(Socket_T);
int check_ftp(Socket_T);
int check_generic(Socket_T);
int check_http(Socket_T);
int check_imap(Socket_T);
int check_clamav(Socket_T);
int check_ldap2(Socket_T);
int check_ldap3(Socket_T);
int check_mysql(Socket_T);
int check_nntp(Socket_T);
int check_ntp3(Socket_T);
int check_postfix_policy(Socket_T);
int check_pop(Socket_T);
int check_smtp(Socket_T);
int check_ssh(Socket_T);
int check_rdate(Socket_T);
int check_rsync(Socket_T);
int check_tns(Socket_T);
int check_pgsql(Socket_T);
int check_sip(Socket_T);
int check_lmtp(Socket_T);
int check_gps(Socket_T);
int check_radius(Socket_T);
int check_memcache(Socket_T);


#endif
