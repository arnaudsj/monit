/*
 * Copyright (C) 2010 Tildeslash Ltd. All rights reserved.
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

/**
 *  System independent filesystem methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */


#include <config.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monitor.h"
#include "device.h"
#include "device_sysdep.h"


/**
 * This function validates whether given object is valid for filesystem
 * informations statistics and stores path suitable for it in given
 * filesystem information structure for later use. Filesystem must be mounted.
 *
 * Valid objects are file or directory that are part of requested
 * filesystem, block special device or mountpoint.
 *
 * In the case of file, directory or mountpoint the result is original
 * object, in the case of block special device mountpoint is returned.
 *
 * @param inf     Information structure where resulting data will be stored
 * @param object  Identifies appropriate device object
 * @return        NULL in the case of failure otherwise filesystem path
 */
char *device_path(Info_T inf, char *object) {

  struct stat buf;

  ASSERT(inf);
  ASSERT(object);

  if(stat(object, &buf) != 0) {
    LogError("%s: Cannot stat '%s' -- %s\n", prog, object, STRERROR);
    return NULL;
  }

  if(S_ISREG(buf.st_mode) || S_ISDIR(buf.st_mode)) {

    inf->mntpath[sizeof(inf->mntpath) - 1] = 0;
    return strncpy(inf->mntpath, object, sizeof(inf->mntpath) - 1);

  } else if(S_ISBLK(buf.st_mode)) {

    return device_mountpoint_sysdep(inf, object);

  }

  LogError("%s: Not file, directory or block special device: '%s'",
    prog, object);

  return NULL;

}


/**
 * Filesystem usage statistics. In the case of success result is stored in
 * given information structure.
 *
 * @param inf Information structure where resulting data will be stored
 * @param object  Identifies requested filesystem - either file, directory,
 *                block special device or mountpoint
 * @return        TRUE if informations were succesfully read otherwise FALSE
 */
int filesystem_usage(Info_T inf, char *object) {

  ASSERT(inf);
  ASSERT(object);

  if(!device_path(inf, object)) {
    return FALSE;
  }

  /* save the previous filesystem flags */
  inf->_flags= inf->flags;

  return filesystem_usage_sysdep(inf);

}

