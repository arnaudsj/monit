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

#include <config.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

/**
 *  Simple Oracle Transparent Network Substrate protocol ping test.
 *
 *  @author Artyom Khafizov, <afk@inbox.ru>
 *
 *  @file
 */

#define TNS_TYPE_REFUSED 4

int check_tns(Socket_T s) {

  unsigned char  buf[STRLEN];

  unsigned char requestPing[] = {
    0x00, 0x57,                           /** Packet Length */
    0x00, 0x00,                           /** Packet Checksum */
    0x01,                                 /** Packet Type: CONNECT */
    0x00,                                 /** Reserved */
    0x00, 0x00,                           /** Header Checksum */
    0x01, 0x36,                           /** Version */
    0x01, 0x2c,                           /** Compatible */
    0x00, 0x00,                           /** Service Options */
    0x08, 0x00,                           /** Session Data Unit Size */
    0x7f, 0xff,                           /** Maximum Transmission Data Unit Size */
    0xa3, 0x0a,                           /** NT Protocol Characteristics */
    0x00, 0x00,                           /** Line Turnaround Value */
    0x01, 0x00,                           /** Value of 1 in Hardware */
    0x00, 0x1d,                           /** Length of Connect Data */
    0x00, 0x3a,                           /** Offset of Connect Data */
    0x00, 0x00, 0x00, 0x00,               /** Maximum Receivable Connect Data */
    0x00,                                 /** Connect flags 0 */
    0x00,                                 /** Connect flags 1 */
    0x00, 0x00, 0x00, 0x00,               /** Trace Cross Facility Item 1 */
    0x00, 0x00, 0x00, 0x00,               /** Trace Cross Facility Item 2 */
    0x00, 0x00, 0x0b, 0x1c,               /** Trace Unique Connection ID */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x28, 0x43, 0x4f, 0x4e,               /** Connect Data */
    0x4e, 0x45, 0x43, 0x54,               /** (CONNECT_DATA=(COMMAND=ping)) */
    0x5f, 0x44, 0x41, 0x54,
    0x41, 0x3d, 0x28, 0x43,
    0x4f, 0x4d, 0x4d, 0x41,
    0x4e, 0x44, 0x3d, 0x70,
    0x69, 0x6e, 0x67, 0x29,
    0x29
  };

  ASSERT(s);

  if(socket_write(s, (unsigned char *)requestPing, sizeof(requestPing)) < 0) {
    LogError("TNS: error sending ping -- %s\n", STRERROR);
    return FALSE;
  }

  /* read just first few bytes which contains enough information */
  if(socket_read(s, (unsigned char *)buf, 5) < 5) {
    LogError("TNS: error receiving ping response -- %s\n", STRERROR);
    return FALSE;
  }

  /* compare packet type */
  if(buf[4] != TNS_TYPE_REFUSED)
  {
    LogError("TNS: invalid ping response\n");
    return FALSE;
  }

  return TRUE;
}

