#ifndef SMALLCLUE_MOUNT_APP_H
#define SMALLCLUE_MOUNT_APP_H

/* Present only where the kernel is Linux: a Linux host, or an embedding that
 * defines SMALLCLUE_HOST_LINUX_MOUNT (see mount_app.c). */
int smallclueMountLinux(int argc, char **argv);
int smallclueUmountLinux(int argc, char **argv);

#endif /* SMALLCLUE_MOUNT_APP_H */
