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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#include "monitor.h"
#include "device_sysdep.h"

/**
 * MacOS X special block device mountpoint method. Filesystem must be mounted.
 * In the case of success, mountpoint is stored in filesystem information
 * structure for later use.
 *
 * @param inf      Information structure where resulting data will be stored
 * @param blockdev Identifies block special device
 * @return         NULL in the case of failure otherwise mountpoint
 */
char *device_mountpoint_sysdep(Info_T inf, char *blockdev) {
  int countfs;

  ASSERT(inf);
  ASSERT(blockdev);

  if ((countfs = getfsstat(NULL, 0, MNT_NOWAIT)) != -1) {
    struct statfs *statfs = xcalloc(countfs, sizeof(struct statfs));
    if ((countfs = getfsstat(statfs, countfs * sizeof(struct statfs), MNT_NOWAIT)) != -1) {
      int i;
      for (i = 0; i < countfs; i++) {
        struct statfs *sfs = statfs + i;
        if (IS(sfs->f_mntfromname, blockdev)) {
          inf->priv.filesystem.mntpath = xstrdup(sfs->f_mntonname);
          FREE(statfs);
          return inf->priv.filesystem.mntpath;
        }
      }
    }
    FREE(statfs);
  }
  LogError("%s: Error getting mountpoint for filesystem '%s' -- %s\n", prog, blockdev, STRERROR);
  return NULL;
}


/**
 * MacOS X filesystem usage statistics. In the case of success result is stored in
 * given information structure.
 *
 * @param inf Information structure where resulting data will be stored
 * @return    TRUE if informations were succesfully read otherwise FALSE
 */
int filesystem_usage_sysdep(Info_T inf) {
  struct statfs usage;

  ASSERT(inf);

  if (statfs(inf->priv.filesystem.mntpath, &usage) != 0) {
    LogError("%s: Error getting usage statistics for filesystem '%s' -- %s\n", prog, inf->priv.filesystem.mntpath, STRERROR);
    return FALSE;
  }
  inf->priv.filesystem.f_bsize =           usage.f_bsize;
  inf->priv.filesystem.f_blocks =          usage.f_blocks;
  inf->priv.filesystem.f_blocksfree =      usage.f_bavail;
  inf->priv.filesystem.f_blocksfreetotal = usage.f_bfree;
  inf->priv.filesystem.f_files =           usage.f_files;
  inf->priv.filesystem.f_filesfree =       usage.f_ffree;
  inf->priv.filesystem.flags =             usage.f_flags;
  return TRUE;
}

