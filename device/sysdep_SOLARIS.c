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
 *  System dependent filesystem methods.
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
# include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#ifdef HAVE_SYS_MNTTAB_H
# include <sys/mnttab.h>
#endif

#include "monitor.h"
#include "device_sysdep.h"


/**
 * Solaris special block device mountpoint method. Filesystem must be mounted.
 * In the case of success, mountpoint is stored in filesystem information
 * structure for later use.
 *
 * @param inf  Information structure where resulting data will be stored
 * @param blockdev Identifies block special device
 * @return         NULL in the case of failure otherwise mountpoint
 */
char *device_mountpoint_sysdep(Info_T inf, char *blockdev) {

  struct mnttab mnt;
  FILE         *mntfd;

  ASSERT(inf);
  ASSERT(blockdev);


  if((mntfd= fopen("/etc/mnttab", "r")) == NULL) {
    LogError("%s: Cannot open /etc/mnttab file\n", prog);
    return NULL;
  }

  /* First match is significant */
  while(getmntent(mntfd, &mnt) == 0) {

    if(IS(blockdev, mnt.mnt_special)) {

      fclose(mntfd);
      inf->mntpath[sizeof(inf->mntpath) - 1] = 0;
      return strncpy(inf->mntpath, mnt.mnt_mountp, sizeof(inf->mntpath) - 1);

    }

  }

  fclose(mntfd);

  return NULL;

}


/**
 * Solaris filesystem usage statistics. In the case of success result is stored in
 * given information structure.
 *
 * @param inf Information structure where resulting data will be stored
 * @return        TRUE if informations were succesfully read otherwise FALSE
 */
int filesystem_usage_sysdep(Info_T inf) {

  struct statvfs usage;

  ASSERT(inf);

  if(statvfs(inf->mntpath, &usage) != 0) {
    LogError("%s: Error getting usage statistics for filesystem '%s' -- %s\n",
        prog, inf->mntpath, STRERROR);
    return FALSE;
  }

  inf->f_bsize=           usage.f_bsize;
  inf->f_blocks=          usage.f_blocks/(usage.f_frsize?(usage.f_bsize/usage.f_frsize):1);
  inf->f_blocksfree=      usage.f_bavail/(usage.f_frsize?(usage.f_bsize/usage.f_frsize):1);
  inf->f_blocksfreetotal= usage.f_bfree/(usage.f_frsize?(usage.f_bsize/usage.f_frsize):1);
  inf->f_files=           usage.f_files;
  inf->f_filesfree=       usage.f_ffree;
  inf->flags=             usage.f_flag;

  return TRUE;

}

