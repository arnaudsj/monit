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


#ifndef MONIT_FILE_H
#define MONIT_FILE_H


/**
 *  Utilities used for managing files used by monit.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */


/**
 * Initialize the programs file variables
 */
void File_init();


/**
 * Finalize and remove temporary files
 */
void File_finalize();


/**
 * Get a object's last modified timestamp.
 * @param object A object to stat
 * @param type Requested object's type
 * @return Max of either st_mtime or st_ctime or
 * FALSE if not found or different type of object
 */
time_t File_getTimestamp(char *object, mode_t type);


/**
 * Search the system for the monit control file. Try first ~/.monitrc,
 * if that fails try /etc/monitrc, then /usr/local/etc/monitrc and
 * finally ./monitrc.  Exit the application if the control file was
 * not found.
 * @return The location of monits control file (monitrc)
 */
char *File_findControlFile();


/**
 * Create a program's pidfile - Such a file is created when in daemon
 * mode. The file is created with mask = MYPIDMASK (usually 644).  
 * @param pidfile The name of the pidfile to create
 * @return TRUE if the file was created, otherwise FALSE. 
 */
int File_createPidFile(char *pidfile);


/**
 * Check if the file is a regular file
 * @param file A path to the file to check
 * @return TRUE if file exist and is a regular file, otherwise FALSE
 */
int File_isFile(char *file);


/**
 * Check if this is a directory.
 * @param dir An absolute  directory path
 * @return TRUE if dir exist and is a regular directory, otherwise
 * FALSE
 */
int File_isDirectory(char *dir);


/**
 * Check if this is a fifo
 * @param fifo A path to the fifo to check
 * @return TRUE if fifo exist, otherwise FALSE
 */
int File_isFifo(char *fifo);


/**
 * Check if the file exist on the system
 * @file A path to the file to check
 * @return TRUE if file exist otherwise FALSE
 */
int File_exist(char *file);


/**
 * Security check for files. The files must have the same uid as the
 * REAL uid of this process, it must have permissions no greater than
 * "maxpermission" and it must not be a symbolic link.  We check these
 * conditions here.
 * @param filename The filename of the checked file
 * @param description The description of the checked file
 * @param permmask The permission mask for the file
 * @return TRUE if the test succeeded otherwise FALSE
 */
int File_checkStat(char *filename, char *description, int permmask);


/**
 * Check whether the specified directory exist or create it using
 * specified mode.
 * @param path The fully qualified path to the directory
 * @param mode The permission for the directory
 * @return TRUE if the succeeded otherwise FALSE
 */
int File_checkQueueDirectory(char *path, mode_t mode);


/**
 * Check the queue size limit.
 * @param path The fully qualified path to the directory
 * @param mode The queue limit
 * @return TRUE if the succeeded otherwise FALSE
 */
int File_checkQueueLimit(char *path, int limit);


/**
 * Write data to the queue file
 * @param file Filedescriptor to write to
 * @param data Data to be written
 * @param size Size of the data to be written
 * @return TRUE if the succeeded otherwise FALSE
 */
int File_writeQueue(FILE *file, void *data, int size);


/**
 * Read the data from the queue file's actual position
 * @param file Filedescriptor to read from
 * @param size Size of the data read
 * @return The data read if any or NULL. The size parameter is set
 * appropriately.
 */
void *File_readQueue(FILE *file, int *size);


#endif
