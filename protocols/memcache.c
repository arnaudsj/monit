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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

#define MEMCACHELEN 24

/* Magic Byte */
#define MAGIC_REQUEST      0x80
#define MAGIC_RESPONSE     0x81

/* Response Status */
#define NO_ERROR           0x0000
#define KEY_NOT_FOUND      0x0001
#define KEY_EXISTS         0x0002
#define VALUE_TOO_BIG      0x0003
#define INVALID_ARGUMENTS  0x0004
#define ITEM_NOT_STORED    0x0005
#define UNKNOWN_COMMAND    0x0081
#define OUT_OF_MEMORY      0x0082

/**
 *  Memcache binary protocol
 *
 *  Send No-op request
 *
 *  @author Sébastien Debrard <sebastien.debrard@gmail.com>
 *
 *  @file
 */
int check_memcache(Socket_T s) {
  unsigned int length;
  unsigned char response[STRLEN];
  unsigned int status;
  
  unsigned char request[MEMCACHELEN] = {
    MAGIC_REQUEST,                    /** Magic */ 
    0x0a,                             /** Opcode */
    0x00, 0x00,                       /** Key length */
    0x00,                             /** Extra length */
    0x00,                             /** Data type */
    0x00, 0x00,                       /** request Reserved / response Status */
    0x00, 0x00, 0x00, 0x00,           /** Total body */
    0x00, 0x00, 0x00, 0x00,           /** Opaque */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00    /** CAS */
  };

  ASSERT(s);

  if(socket_write(s, (unsigned char *)request, sizeof(request)) <= 0) {
    LogError("MEMCACHE: error sending data -- %s\n", STRERROR);
    return FALSE;
  }

  /* Response should have at least MEMCACHELEN bytes */
  length = socket_read(s, (unsigned char *)response, sizeof(response));
  if (length != MEMCACHELEN) {
    LogError("MEMCACHE: Received %d bytes from server, expected %d bytes\n", length, MEMCACHELEN);
    return FALSE;
  }

  if(response[0] != MAGIC_RESPONSE) {
    LogError("MEMCACHELEN: Invalid response code -- error occured\n");
    return FALSE;
  }

  status = (response[6] << 8) | response[7];
  switch( status ) {
    case NO_ERROR:
      return TRUE;
    case OUT_OF_MEMORY:
      LogError("MEMCACHELEN: Invalid response code -- Out of memory\n");
      return FALSE;
    case UNKNOWN_COMMAND:
      LogError("MEMCACHELEN: Invalid response code -- Unknown command\n");
      return FALSE;
    case INVALID_ARGUMENTS:
      LogError("MEMCACHELEN: Invalid response code -- Invalid arguments\n");
      return FALSE;
    case VALUE_TOO_BIG:
      LogError("MEMCACHELEN: Invalid response code -- Value too big\n");
      return FALSE;
    case ITEM_NOT_STORED:
      LogError("MEMCACHELEN: Invalid response code -- Item not stored\n");
      return FALSE;
    case KEY_NOT_FOUND:
      LogError("MEMCACHELEN: Invalid response code -- Key not found\n");
      return FALSE;
    case KEY_EXISTS:
      LogError("MEMCACHELEN: Invalid response code -- Key exists\n");
      return FALSE;
    default:
      LogError("MEMCACHELEN: Unknow response code %u -- error occured\n", status);
      return FALSE;
  }

  return FALSE;
    
}

 
