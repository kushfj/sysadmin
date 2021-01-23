#!/usr/bin/bash
#
# Bash script to be used on Windows systems with Cygwin and Rsync installed to 
# perform time machine like backups of files from the source directory to a
# destination location.
#
# References:
#   https://robservatory.com/create-time-machine-like-backups-via-rsync/
#   https://web.archive.org/web/20170708224601/https://blog.interlinked.org/tutorials/rsync_time_machine.html
#   http://www.mikerubel.org/computers/rsync_snapshots/
#
# TODO:
#   * Test backup to/from remote SSH location
#   * Use --copy-dest to allow multiple source locations to be specified



# Rsync command - location of the rsync command
RSYNC=/cygdrive/c/ProgramData/chocolatey/bin/rsync

# Source directory - where to copy files from
#  Can be a local directory or a remote location, if a trailing slash is specified that sub-directories are not copied
#  e.g. /home/users, user@host:/home/users
SOURCEDIR=/cygdrive/d/Users

# Target directory - where to copy files to
#  Can be a local directory or a remote location
#  e.g. /var/backup/, user@host:/var/backup/
TARGETDIR=/cygdrive/e/backup

# Exclude patterns - files containing lines of patterns to exclude from backup
#  If nothing is to be excluded just recreate an empty file
#  Recommend including *~, *.swo and *.swp to exclude temporary Vi/Vim files
EXFILE=./rsync_exclude.txt



## Do not edit the variables below this line ##
TIMESTAMP=`date "+%Y-%m-%dT%H-%M-%S"`
CURRDIR="$TARGETDIR/latest"
DESTDIR="$TARGETDIR/$TIMESTAMP"
PROGDIR="$DESTDIR-part"
FAILDIR="$DESTDIR-failed"
LOGFILE="$TARGETDIR/backup.log"

# Rsync options - options specified to the rsync command
# -a archive mode; equals -rlptgoD (no -H,-A,-X)
#   -r recursive
#   -l copy symlinks as symlinks
#   -p preserve permissions
#   -t preserve modification times
#   -g preserve group
#   -o preserve owner
#   -D preserve device and special files
# -z compress files during transfer (useful for remote locations)
# -h human readable output
# -P show progress
# --exclude-from=FILE exclude patterns from file
# --delete delete extra files in destination which is not in source
# --delete_excluded delete excluded files from destination
# --log-file file to log to
# --link-dest=DIR hardlink to files in DIR when file is unchanged
# -n dry run only
#OPTS="-azhP --delete --delete-excluded -n"
OPTS="-azhP --delete --delete-excluded"



## Script

# Execute the rsync command
echo "[+] starting backup..."
$RSYNC $OPTS --exclude-from=$EXFILE --log-file=$LOGFILE --link-dest=$CURRDIR $SOURCEDIR $PROGDIR

# Check exit status to see if rsyn succeeded
if [ "$?" = 0 ]; then
  # Change partial progress directory name to completed backup name
  mv $PROGDIR $DESTDIR

  # Delete the current directory link
  rm -f $CURRDIR

  # Link the current directory to the most recent backup
  ln -s $DESTDIR $CURRDIR

  echo "[+] backup completed successfully!"
else
  # Change partial progress directory name to failed backup name
  mv $PROGDIR $FAILDIR
  echo "[!] backup failed!"
fi

echo "[-] please review the log file at $LOGFILE and delete it"
