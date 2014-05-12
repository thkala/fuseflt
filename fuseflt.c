/*
 * fuseflt - A FUSE filesystem with file conversion filter support
 *
 * Copyright (c) 2007 Theodoros V. Kalamatianos <nyb@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 *
 * Compilation:
 *
 * gcc -Wall `pkg-config fuse --cflags --libs` -lcfg+ fuseflt.c -o fuseflt
 */



#define DEBUG		0

#define FDC_MAX_AGE	120
#define FDC_CHK_INT	5



#define _GNU_SOURCE

#define FUSE_USE_VERSION 26

#include <cfg+.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <pthread.h>
#include <search.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>



static char *src = NULL;



#define ADJPATH		char t[PATH_MAX + 1]; \
			strncpy(t, src, PATH_MAX); \
			strncat(t, path, PATH_MAX - strlen(src)); \
			path = t;
#define EXTPATH		int f __attribute__ ((unused)) = flt_path((char *)path);
#define TRYERR(c) 	int res = (c); \
			if (res == -1) \
				return -errno;
#define TRYRET(c)	TRYERR(c) \
			return 0;

#if DEBUG
#define DBGMSG(M, ...)	fprintf(stderr, "%s:%s:%i " M "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); fflush(stderr);
#else
#define DBGMSG(M, ...)
#endif



static char **flt_in, **flt_out, **flt_cmd, **ext_in, **ext_out;



static int flt_path(char *path)
{
	struct stat st;

	if (lstat(path, &st) == 0)
		return -1;

	int l = strlen(path);

	int i = 0;
	while ((flt_in[i] != NULL) && (flt_out[i] != NULL) && (flt_cmd[i] != NULL)) {
		if (flt_cmd[i][0] == 0)
			continue;

		char t[PATH_MAX + 1];
		int ixl = strlen(flt_in[i]), oxl = strlen(flt_out[i]);

		if (((l - oxl) < 1) ||
				(path[l - oxl - 1] == '/') ||
				((l - oxl + ixl) > PATH_MAX) ||
				(strncmp(path + l - oxl, flt_out[i], oxl) != 0)) {
			++i;
			continue;
		}

		strncpy(t, path, PATH_MAX);
		t[l - oxl] = '\0';
		strncat(t, flt_in[i], PATH_MAX - l + oxl);

		int r = stat(t, &st);
		if ((r == 0) && ((S_ISREG(st.st_mode)) || ((ixl == 0) && (oxl == 0)))) {
			strncpy(path, t, PATH_MAX);
			return i;
		}

		++i;
	}

	return -1;
}



static void *fdc = NULL;

static int fdc_nr = 0;
static int fdc_nr_max = 0;

static int fdc_ghost_tmp = 1;

static pthread_t fdc_expire_thread;
static pthread_mutex_t fdc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int fdc_expire_thread_stop = 0;

static int fdc_max_age = FDC_MAX_AGE;
static int fdc_chk_int = FDC_CHK_INT;

typedef struct __fdcent_t {
	char path[PATH_MAX];
	struct timeval et;
	struct stat st;
	int fd;
	char *tfn;
} fdcent_t;

/* The temporary file directory */
static char *tmpdir = "/tmp";

/* Expiration threshold */
static struct timeval tt;

/* A temporary binary tree */
static void *ttmp = NULL;

static int fdcentcmp(const void *n1, const void *n2)
{
	return strncmp(((const fdcent_t *)n1)->path,
		((const fdcent_t *)n2)->path, PATH_MAX);
}

static void fdc_clear(int e);
static void fdc_prune(int n);

#define RET(r)	{ free(vpath); return(r); }
#define ERR(x)	{ res = -errno; x; RET(res) }
static int fdc_open(const char *path, struct stat *stbuf)
{
	int res, rfd;
        char *vpath = strdup(path);
	fdcent_t *fdcent, **fdcres, fdctmp;

	ADJPATH
	EXTPATH

	/* Search the file descriptor cache */
	strncpy(fdctmp.path, vpath, PATH_MAX);
	pthread_mutex_lock(&fdc_mutex);
	fdcres = tfind(&fdctmp, &fdc, fdcentcmp);
	if (fdcres != NULL) {
		DBGMSG("fdc: retrieve %s", vpath);

		gettimeofday(&((*fdcres)->et), NULL);

		if (stbuf != NULL) {
			rfd = 0;
			*stbuf = (*fdcres)->st;
		} else if (fdc_ghost_tmp) {
			rfd = dup((*fdcres)->fd);
			if (rfd == -1) {
				rfd = -errno;
				DBGMSG("fdc: cache FD duplication failure [%s]",
					vpath);
			}
		} else {
			rfd = open((*fdcres)->tfn, O_RDONLY);
			if (rfd == -1) {
				rfd = -errno;
				DBGMSG("fdc: cache file open failure [%s:%s]",
					vpath, (*fdcres)->tfn);
			}
		}

		pthread_mutex_unlock(&fdc_mutex);
		RET(rfd)
	}
	pthread_mutex_unlock(&fdc_mutex);

	if (f < 0) {
		if (stbuf == NULL) {
			rfd = open(path, O_RDONLY);
			if (rfd == -1)
				RET(-errno)
		} else {
			rfd = lstat(path, stbuf);
			if (rfd == -1)
				RET(-errno)
		}
	} else {
		int ifd = open(path, O_RDONLY);
		if (ifd == -1)
			RET(-errno)

		struct stat st;

		char tfn[PATH_MAX + 1];
		snprintf(tfn, PATH_MAX + 1, "%s/.fuseflt.XXXXXX", tmpdir);

		int ofd = mkstemp(tfn);
		if (ofd == -1)
			ERR(
				DBGMSG("flt: unable to create temporary file (err=%i)", errno)
				close(ifd)
			)

		if (fdc_ghost_tmp)
			unlink(tfn);

		pid_t pid = fork();
		if (pid == -1) {
			ERR(
				DBGMSG("flt: fork() failed (err=%i)", errno)
				close(ifd)
			)
		} else if (pid != 0) {
			int ws;
			struct stat tst;

			res = waitpid(pid, &ws, 0);

			/* Get the stat(2) information */
			fstat(ifd, &st);
			fstat(ofd, &tst);
			st.st_size = tst.st_size;
			st.st_blksize = tst.st_blksize;
			st.st_blocks = tst.st_blocks;
			st.st_mode &= ~(S_IWUSR|S_IWGRP|S_IWOTH);

			close(ifd);
			if (res == -1)
				ERR(close(ofd))
		} else {
			dup2(ifd, fileno(stdin));
			dup2(ofd, fileno(stdout));
			res = execlp("/bin/sh", "/bin/sh", "-c", flt_cmd[f], (char *)NULL);
			exit(errno);
		}

		fsync(ofd);
		lseek(ofd, 0, SEEK_SET);
		fcntl(ofd, F_SETFL, O_RDONLY);

		rfd = ofd;

		/* Prepare the file descriptor cache entry */
		fdcent = malloc(sizeof(*fdcent));
		if (fdcent == NULL)
			ERR(close(rfd))
		strncpy(fdcent->path, vpath, PATH_MAX);
		gettimeofday(&(fdcent->et), NULL);
		fdcent->st = st;
		if (fdc_ghost_tmp) {
			fdcent->fd = dup(rfd);
			fdcent->tfn = NULL;
		} else {
			fdcent->fd = -1;
			fdcent->tfn = strdup(tfn);
		}
		fcntl(fdcent->fd, FD_CLOEXEC, 1);

		/* Cache the file descriptor for future use */
		DBGMSG("fdc: insert %s", vpath);
		pthread_mutex_lock(&fdc_mutex);
		if (fdc_nr >= fdc_nr_max)
			fdc_prune(fdc_nr_max / 4);
		fdcres = tsearch(fdcent, &fdc, fdcentcmp);
		if (fdcres == NULL) {
			ERR(
				if (fdc_ghost_tmp) {
					close(fdcent->fd);
				} else {
					unlink(fdcent->tfn);
					free(fdcent->tfn);
				}
				free(fdcent);
				close(rfd);

				pthread_mutex_unlock(&fdc_mutex);
			)
		} else if (*fdcres != fdcent) {
			(*fdcres)->et = fdcent->et;
			if (fdc_ghost_tmp) {
				close((*fdcres)->fd);
				(*fdcres)->fd = fdcent->fd;
			} else {
				unlink((*fdcres)->tfn);
				free((*fdcres)->tfn);
				(*fdcres)->tfn = fdcent->tfn;
			}
			free(fdcent);
		} else {
			++fdc_nr;
		}
		pthread_mutex_unlock(&fdc_mutex);

		if (stbuf != NULL) {
			close(rfd);
			rfd = 0;
			*stbuf = (*fdcres)->st;
		}
	}

	RET(rfd)
}

static void fdc_walk_delete_removed(const void *p, const VISIT v, const int d)
{
	if ((v == endorder) || (v == leaf))
		tdelete(*((fdcent_t **)p), &fdc, fdcentcmp);
}

static void fdc_free(void *p) {
	DBGMSG("fdc: remove %s", ((fdcent_t *)p)->path);
	if (fdc_ghost_tmp) {
		close(((fdcent_t *)p)->fd);
	} else {
		unlink(((fdcent_t *)p)->tfn);
		free(((fdcent_t *)p)->tfn);
	}
	--fdc_nr;
	free(p);
}

static void fdc_expire_mark(const void *p, const VISIT v, const int d)
{
	if ((v == endorder) || (v == leaf))
		if ((*((fdcent_t **)p))->et.tv_sec < tt.tv_sec) {
			DBGMSG("fdc: expiration mark %s", (*((fdcent_t **)p))->path);
			tsearch(*((fdcent_t **)p), &ttmp, fdcentcmp);
		}
}

static void *fdc_expire(void *arg)
{
	while (!fdc_expire_thread_stop) {
		sleep(fdc_chk_int);

		DBGMSG("fdc: expiration check [i=%i,m=%i,n=%i/%i]",
			fdc_chk_int, fdc_max_age, fdc_nr, fdc_nr_max);

		gettimeofday(&tt, NULL);
		tt.tv_sec -= fdc_max_age;

		pthread_mutex_lock(&fdc_mutex);

		twalk(fdc, fdc_expire_mark);
		twalk(ttmp, fdc_walk_delete_removed);

		tdestroy(ttmp, fdc_free);
		ttmp = NULL;

		pthread_mutex_unlock(&fdc_mutex);
	}

	return NULL;
}

static void fdc_clear(int e)
{
	DBGMSG("fdc: clearing cache");

	pthread_mutex_lock(&fdc_mutex);
	tdestroy(fdc, fdc_free);
	fdc = NULL;
	pthread_mutex_unlock(&fdc_mutex);
}

static void fdc_prune_mark(const void *p, const VISIT v, const int d)
{
	if ((fdc_nr > 0) && ((v == endorder) || (v == leaf))) {
		DBGMSG("fdc: prune mark %s", (*((fdcent_t **)p))->path);
		tsearch(*((fdcent_t **)p), &ttmp, fdcentcmp);
		--fdc_nr;
	}
}

static void fdc_prune(int n)
{
	int k;

	k = fdc_nr;
	fdc_nr = n;

	twalk(fdc, fdc_prune_mark);

	fdc_nr = k;

	twalk(ttmp, fdc_walk_delete_removed);

	tdestroy(ttmp, fdc_free);
	ttmp = NULL;
}


static int flt_getattr(const char *path, struct stat *stbuf)
{
	return fdc_open(path, stbuf);
}

static int flt_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	TRYRET(fstat(fi->fh, stbuf))
}

static int flt_access(const char *path, int mask)
{
	ADJPATH
	EXTPATH
	TRYRET(access(path, mask))
}

static int flt_readlink(const char *path, char *buf, size_t size)
{
	ADJPATH
	EXTPATH
	TRYERR(readlink(path, buf, size - 1))

	buf[res] = '\0';
	return 0;
}

static int flt_opendir(const char *path, struct fuse_file_info *fi)
{
	ADJPATH

	DIR *dp = opendir(path);
	if (dp == NULL)
    		return -errno;

	fi->fh = (unsigned long) dp;
	return 0;
}

static int flt_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    		off_t offset, struct fuse_file_info *fi)
{
	DIR *dp = (DIR *) (uintptr_t) fi->fh;
	struct dirent *de;
	struct stat st;

	seekdir(dp, offset);
	while ((de = readdir(dp)) != NULL) {
		fstatat(dirfd(dp), de->d_name, &st, 0);

		if (S_ISREG(st.st_mode)) {
			int i = 0;

			int l = strlen(de->d_name);
			while ((ext_in[i] != NULL) && (ext_out[i] != NULL)) {
				int ixl = strlen(ext_in[i]);
				int oxl = strlen(ext_out[i]);

				if (((l - ixl) < 1) || ((l - ixl + oxl) > NAME_MAX) ||
						(strncmp(de->d_name + l - ixl, ext_in[i], ixl) != 0)) {
					++i;
					continue;
				}

				de->d_name[l - ixl] = '\0';
				strncat(de->d_name, ext_out[i], NAME_MAX - l + ixl);

				/* Avoid duplicate filenames */
				if (fstatat(dirfd(dp), de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
					/* Reverse the name change */
					de->d_name[l - ixl] = '\0';
					strncat(de->d_name, ext_in[i], NAME_MAX - l + ixl);
				}
				break;
			}
		}

        	memset(&st, 0, sizeof(st));
        	st.st_ino = de->d_ino;
        	st.st_mode = de->d_type << 12;
        	if (filler(buf, de->d_name, &st, telldir(dp)))
        		break;
	}

	return 0;
}

static int flt_releasedir(const char *path, struct fuse_file_info *fi)
{
	closedir((DIR*) (uintptr_t) fi->fh);
	return 0;
}

static int flt_open(const char *path, struct fuse_file_info *fi)
{
	int fd = fdc_open(path, NULL);
	if (fd < 0)
		return fd;

	fi->fh = fd;

	return 0;
}

static int flt_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
	TRYERR(pread(fi->fh, buf, size, offset))
	return res;
}

static int flt_statfs(const char *path, struct statvfs *stbuf)
{
	ADJPATH
	EXTPATH
	TRYRET(statvfs(path, stbuf))
}

static int flt_flush(const char *path, struct fuse_file_info *fi)
{
	TRYRET(close(dup(fi->fh)))
}

static int flt_release(const char *path, struct fuse_file_info *fi)
{
	close(fi->fh);
	return 0;
}


static void *flt_init(struct fuse_conn_info *conn)
{
	/* The file descriptor cache expiry thread */
	pthread_create(&fdc_expire_thread, NULL, fdc_expire, NULL);

	return NULL;
}

static void flt_arrstr_free(char **c)
{
	int i;

	for (i = 0; c[i] != NULL; i++)
		free(c[i]);

	free(c);
}

static void flt_destroy(void *p)
{
	fdc_clear(0);

	fdc_expire_thread_stop = 1;
	pthread_kill(fdc_expire_thread, SIGINT);
	pthread_join(fdc_expire_thread, NULL);

	flt_arrstr_free(flt_in);
	flt_arrstr_free(flt_out);
	flt_arrstr_free(flt_cmd);
	flt_arrstr_free(ext_in);
	flt_arrstr_free(ext_out);
	free(src);
}



static struct fuse_operations flt_oper = {
	.getattr	= flt_getattr,
	.fgetattr	= flt_fgetattr,
	.access		= flt_access,
	.readlink	= flt_readlink,
	.opendir	= flt_opendir,
	.readdir	= flt_readdir,
	.releasedir	= flt_releasedir,
	.open		= flt_open,
	.read		= flt_read,
	.statfs		= flt_statfs,
	.flush		= flt_flush,
	.release	= flt_release,
	.init		= flt_init,
	.destroy	= flt_destroy,
};



int main(int argc, char *argv[])
{
	int cwdfd, i, o, pargc = argc;
	char **pargv;


	cwdfd = open(".", O_RDONLY);

	pargv = malloc(argc * sizeof(char *));
	if (pargv == NULL) {
		perror("Command line argument processing failed");
		return errno;
	}
	pargv[0] = argv[0];


	for (i = 1; i < (argc); ++i)
		if (strcmp("-h", argv[i]) == 0) {
			pargc = 1;
			break;
		}

	if (pargc < 4) {
		printf("\nfuseflt %s - A FUSE filesystem with file conversion filter support\n"
		       "Copyright (c) 2007 Theodoros V. Kalamatianos <nyb@users.sourceforge.net>\n\n",
		       VERSION);

		pargv[0] = malloc(strlen(argv[0]) + strlen(" configfile sourcedir") + 1);
		if (pargv[0] == NULL) {
			perror("Command line argument processing failed");
			return errno;
		}

		sprintf(pargv[0],"%s%s", argv[0], " configfile sourcedir");

		pargv[1] = "-h";
		pargc = 2;
	} else {
		int f = 0;
		for (i = 1; i < argc; ++i) {
			if ((f == 0) && (argv[i][0] != '-')) {
				CFG_CONTEXT con;
				int ret;

				char *arg = strdup(argv[i]);

				struct cfg_option options[] = {
					{NULL, '\0', "cache_chk_int", CFG_INT, (void *) &fdc_chk_int, 0},
					{NULL, '\0', "cache_max_age", CFG_INT, (void *) &fdc_max_age, 0},
					{NULL, '\0', "cache_max_nr", CFG_INT, (void *) &fdc_nr_max, 0},
					{NULL, '\0', "temp_dir", CFG_STR, (void *) &tmpdir, 0},
					{NULL, '\0', "ghost_temp", CFG_INT, (void *) &fdc_ghost_tmp, 0},

					{NULL, '\0', "flt_in", CFG_STR+CFG_MULTI, (void *) &flt_in, 0},
					{NULL, '\0', "flt_out", CFG_STR+CFG_MULTI, (void *) &flt_out, 0},
					{NULL, '\0', "flt_cmd", CFG_STR+CFG_MULTI, (void *) &flt_cmd, 0},
					{NULL, '\0', "ext_in", CFG_STR+CFG_MULTI, (void *) &ext_in, 0},
					{NULL, '\0', "ext_out", CFG_STR+CFG_MULTI, (void *) &ext_out, 0},

					CFG_END_OF_LIST
				};

				/*
				 * Allow the configuration file and source directory to be supplied in a
				 * single stroke, so that fuseflt can be mounted from /etc/fstab.
				 */
				if (arg[0] == '#') {
					src = strstr(&(arg[1]), "##");

					if (src != NULL) {
						*src = '\0';
						src += 2;

						o = chdir(src);
						if (o == -1) {
							free(arg);
							perror("Cannot enter source directory");
							return errno;
						}
						src = get_current_dir_name();
						fchdir(cwdfd);
					}
				}

				con = cfg_get_context(options);
				if (con == NULL) {
					free(arg);
					perror("Configuration file processing failed");
					return errno;
				}

				cfg_set_cfgfile_context(con, 0, -1, (src != NULL)?(&(arg[1])):arg);

				ret = cfg_parse(con);
				if (ret != CFG_OK) {
					free(arg);
					fprintf(stderr, "Configuration file processing failed: ");
					cfg_fprint_error(con, stderr);
					fprintf(stderr, "\n");
                    			return ret < 0 ? -ret : ret;
            			}

				cfg_free_context(con);

				free(arg);
				pargc--;
				++f;
				continue;
			} else if ((f == 1) && (src == NULL) && (argv[i][0] != '-')) {
				o = chdir(argv[i]);
				if (o == -1) {
					perror("Cannot enter source directory");
					return errno;
				}
				src = get_current_dir_name();
				fchdir(cwdfd);

				pargc--;
				++f;
				continue;
			}

			pargv[i - f] = argv[i];
		}
	}

	close(cwdfd);
	umask(077);

	/* Use `ghost' temporary files or not ? */
	if (fdc_ghost_tmp != 0)
		fdc_ghost_tmp = 1;

	/* Get a proper value for fdc_nr_max */
	if (fdc_ghost_tmp) {
		o = sysconf(_SC_OPEN_MAX) - 64;
		if (fdc_nr_max == 0)
			fdc_nr_max = o / 2;
		else if (fdc_nr_max > o)
			fdc_nr_max = o;
	} else {
		if (fdc_nr_max == 0)
			fdc_nr_max = 2048;
	}

	/* Allow SIGUSR1 to clear the cache */
	signal(SIGUSR1, fdc_clear);

	DBGMSG("temp_dir = %s", tmpdir);

	o = fuse_main(pargc, pargv, &flt_oper, NULL);

	free(pargv);

	return o;
}
