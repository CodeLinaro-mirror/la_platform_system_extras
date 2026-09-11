/* Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/*
 * secure-fscryptctl.c - Userspace helper for FSPAPP-backed fscrypt v2
 *
 * This utility never handles the raw fscrypt key.
 *
 * It reads a wrapped key blob from persistent storage, passes it to the
 * /dev/fspapp_fscrypt kernel driver, receives the non-secret fscrypt v2
 * master_key_identifier, and optionally applies FSCRYPT_POLICY_V2 to a
 * directory.
 *
 * Typical boot usage:
 *
 *   secure-fscryptctl \
 *        --ensure \
 *        --mount /lcm \
 *        --dir /lcm/secure \
 *        --blob /cfg/wrapped_key.mbn
 *
 * Modes:
 *   --unlock
 *      Add fscrypt key to the filesystem keyring only.
 *
 *   --provision
 *      Add key and apply FSCRYPT_POLICY_V2 to an empty directory.
 *      Intended for one-time/manual provisioning.
 *
 *   --ensure
 *      Add key, create the directory if missing, and apply or validate
 *      FSCRYPT_POLICY_V2. This is suitable for init-script boot use.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/fscrypt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fspapp_fscrypt.h"

#define DEFAULT_DEVICE "/dev/fspapp_fscrypt"
//#define DEFAULT_BLOB   "/persist/secure_datakey.mbn"

enum action {
	ACTION_NONE = 0,
	ACTION_UNLOCK,
	ACTION_PROVISION,
	ACTION_ENSURE,
};

struct options {
	enum action action;
	const char *mountpoint;
	const char *dirpath;
	const char *blob_path;
	const char *device_path;
	bool verbose;
};

static void secure_memzero(void *ptr, size_t len)
{
	volatile unsigned char *p = ptr;

	while (len--)
		*p++ = 0;
}

static void log_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "secure-fscryptctl: ERROR: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static void log_info(const struct options *opts, const char *fmt, ...)
{
	va_list ap;

	if (!opts || !opts->verbose)
		return;

	va_start(ap, fmt);
	fprintf(stdout, "secure-fscryptctl: ");
	vfprintf(stdout, fmt, ap);
	fprintf(stdout, "\n");
	va_end(ap);
}

/*
static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --unlock --mount <mountpoint> [--blob <path>] [--device <dev>] [--verbose]\n"
		"  %s --provision --mount <mountpoint> --dir <empty-dir> [--blob <path>] [--device <dev>] [--verbose]\n"
		"  %s --ensure --mount <mountpoint> --dir <dir> [--blob <path>] [--device <dev>] [--verbose]\n"
		"\n"
		"Examples:\n"
		"  %s --unlock --mount /data\n"
		"  %s --provision --mount /data --dir /data/secure\n"
		"  %s --ensure --mount /data --dir /data/secure\n"
		"\n"
		"Options:\n"
		"  -u, --unlock          Add fscrypt key to filesystem keyring only\n"
		"  -p, --provision       Add key and apply FSCRYPT_POLICY_V2 to empty dir\n"
		"  -e, --ensure          Create dir if missing and apply/validate policy\n"
		"  -m, --mount PATH      Filesystem mountpoint, for example /data\n"
		"  -d, --dir PATH        Directory to encrypt, for example /data/secure\n"
		"  -b, --blob PATH       Wrapped key blob, default /persist/secure_datakey.mbn\n"
		"  -D, --device PATH     Kernel device, default /dev/fspapp_fscrypt\n"
		"  -v, --verbose         Print diagnostic messages\n"
		"  -h, --help            Show this help\n",
		prog, prog, prog, prog, prog, prog);
}
*/

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --unlock --mount <mountpoint> --blob <path> [--device <path>] [--verbose]\n"
		"  %s --provision --mount <mountpoint> --dir <dir> --blob <path> [--device <path>] [--verbose]\n"
		"  %s --ensure --mount <mountpoint> --dir <dir> --blob <path> [--device <path>] [--verbose]\n"
		"\n"
		"Examples:\n"
		"  %s --unlock --mount /lcm --blob /cfg/wrapped_key.mbn\n"
		"  %s --provision --mount /lcm --dir /lcm/secure --blob /cfg/wrapped_key.mbn\n"
		"  %s --ensure --mount /lcm --dir /lcm/secure --blob /cfg/wrapped_key.mbn\n"
		"\n"
		"Options:\n"
		"  -u, --unlock          Add fscrypt key to filesystem keyring only\n"
		"  -p, --provision       Add key and apply FSCRYPT_POLICY_V2 to empty dir\n"
		"  -e, --ensure          Create dir if missing and apply/validate policy\n"
		"  -m, --mount PATH      Filesystem mountpoint, for example /lcm\n"
		"  -d, --dir PATH        Directory to encrypt, for example /lcm/secure\n"
		"  -b, --blob PATH       Wrapped key blob path. Usually passed from /etc/config/secure-fscrypt\n"
		"  -D, --device PATH     Kernel device, default /dev/fspapp_fscrypt\n"
		"  -v, --verbose         Print diagnostic messages\n"
		"  -h, --help            Show this help\n",
		prog, prog, prog, prog, prog, prog);
}
static void print_identifier(const uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	size_t i;

	for (i = 0; i < FSCRYPT_KEY_IDENTIFIER_SIZE; i++)
		printf("%02x", identifier[i]);

	printf("\n");
}
/*
static int parse_options(int argc, char **argv, struct options *opts)
{
	static const struct option long_options[] = {
		{ "unlock",    no_argument,       NULL, 'u' },
		{ "provision", no_argument,       NULL, 'p' },
		{ "ensure",    no_argument,       NULL, 'e' },
		{ "mount",     required_argument, NULL, 'm' },
		{ "dir",       required_argument, NULL, 'd' },
		{ "blob",      required_argument, NULL, 'b' },
		{ "device",    required_argument, NULL, 'D' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{ }
	};

	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->action = ACTION_NONE;
	opts->blob_path = DEFAULT_BLOB;
	opts->device_path = DEFAULT_DEVICE;

	while ((opt = getopt_long(argc, argv, "upem:d:b:D:vh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'u':
			if (opts->action != ACTION_NONE) {
				log_err("only one action is allowed");
				return -EINVAL;
			}
			opts->action = ACTION_UNLOCK;
			break;

		case 'p':
			if (opts->action != ACTION_NONE) {
				log_err("only one action is allowed");
				return -EINVAL;
			}
			opts->action = ACTION_PROVISION;
			break;

		case 'e':
			if (opts->action != ACTION_NONE) {
				log_err("only one action is allowed");
				return -EINVAL;
			}
			opts->action = ACTION_ENSURE;
			break;

		case 'm':
			opts->mountpoint = optarg;
			break;

		case 'd':
			opts->dirpath = optarg;
			break;

		case 'b':
			opts->blob_path = optarg;
			break;

		case 'D':
			opts->device_path = optarg;
			break;

		case 'v':
			opts->verbose = true;
			break;

		case 'h':
			usage(argv[0]);
			return 1;

		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (opts->action == ACTION_NONE) {
		log_err("missing action: use --unlock, --provision, or --ensure");
		usage(argv[0]);
		return -EINVAL;
	}

	if (!opts->mountpoint) {
		log_err("missing required option: --mount");
		usage(argv[0]);
		return -EINVAL;
	}

	if ((opts->action == ACTION_PROVISION ||
	     opts->action == ACTION_ENSURE) &&
	    !opts->dirpath) {
		log_err("--dir is required with --provision or --ensure");
		usage(argv[0]);
		return -EINVAL;
	}

	if (opts->action == ACTION_UNLOCK && opts->dirpath) {
		log_err("--dir is only valid with --provision or --ensure");
		usage(argv[0]);
		return -EINVAL;
	}

	return 0;
}
*/

static int parse_options(int argc, char **argv, struct options *opts)
{
	static const struct option long_options[] = {
		{ "unlock",    no_argument,       NULL, 'u' },
		{ "provision", no_argument,       NULL, 'p' },
		{ "ensure",    no_argument,       NULL, 'e' },
		{ "mount",     required_argument, NULL, 'm' },
		{ "dir",       required_argument, NULL, 'd' },
		{ "blob",      required_argument, NULL, 'b' },
		{ "device",    required_argument, NULL, 'D' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{ NULL,        0,                 NULL,  0  },
	};
	int c;

	memset(opts, 0, sizeof(*opts));

	opts->action = ACTION_NONE;
	opts->mountpoint = NULL;
	opts->dirpath = NULL;
	opts->blob_path = NULL;
	opts->device_path = DEFAULT_DEVICE;
	opts->verbose = false;

	while ((c = getopt_long(argc, argv, "upem:d:b:D:vh",
				long_options, NULL)) != -1) {
		switch (c) {
		case 'u':
			if (opts->action != ACTION_NONE) {
				log_err("only one action can be specified");
				return -EINVAL;
			}
			opts->action = ACTION_UNLOCK;
			break;

		case 'p':
			if (opts->action != ACTION_NONE) {
				log_err("only one action can be specified");
				return -EINVAL;
			}
			opts->action = ACTION_PROVISION;
			break;

		case 'e':
			if (opts->action != ACTION_NONE) {
				log_err("only one action can be specified");
				return -EINVAL;
			}
			opts->action = ACTION_ENSURE;
			break;

		case 'm':
			opts->mountpoint = optarg;
			break;

		case 'd':
			opts->dirpath = optarg;
			break;

		case 'b':
			opts->blob_path = optarg;
			break;

		case 'D':
			opts->device_path = optarg;
			break;

		case 'v':
			opts->verbose = true;
			break;

		case 'h':
			usage(argv[0]);
			return 1;

		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (opts->action == ACTION_NONE) {
		log_err("missing action: use --unlock, --provision, or --ensure");
		usage(argv[0]);
		return -EINVAL;
	}

	if (!opts->mountpoint) {
		log_err("missing required --mount argument");
		usage(argv[0]);
		return -EINVAL;
	}

	if ((opts->action == ACTION_PROVISION ||
	     opts->action == ACTION_ENSURE) &&
	    !opts->dirpath) {
		log_err("missing required --dir argument");
		usage(argv[0]);
		return -EINVAL;
	}

	if (!opts->blob_path) {
		log_err("wrapped key blob not specified; pass --blob PATH or configure it in /etc/config/secure-fscrypt");
		usage(argv[0]);
		return -EINVAL;
	}

	return 0;
}

static int open_directory(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		log_err("failed to open directory '%s': %s",
			path, strerror(errno));

	return fd;
}

static int ensure_directory_exists(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("path '%s' exists but is not a directory", path);
			return -ENOTDIR;
		}
		return 0;
	}

	if (errno != ENOENT) {
		log_err("stat failed for '%s': %s", path, strerror(errno));
		return -errno;
	}

	if (mkdir(path, 0700) < 0) {
		log_err("mkdir failed for '%s': %s", path, strerror(errno));
		return -errno;
	}

	return 0;
}

static int read_wrapped_blob(const char *path,
			     uint8_t *buf,
			     size_t max_size,
			     uint32_t *out_size)
{
	struct stat st;
	ssize_t total = 0;
	int fd;

	if (!path || !buf || !out_size)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		log_err("failed to open blob '%s': %s",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st) < 0) {
		log_err("fstat failed for '%s': %s",
			path, strerror(errno));
		close(fd);
		return -errno;
	}

	if (!S_ISREG(st.st_mode)) {
		log_err("blob path '%s' is not a regular file", path);
		close(fd);
		return -EINVAL;
	}

	if (st.st_size <= 0 || (uint64_t)st.st_size > max_size) {
		log_err("invalid blob size %lld for '%s', max=%zu",
			(long long)st.st_size, path, max_size);
		close(fd);
		return -EINVAL;
	}

	while (total < st.st_size) {
		ssize_t n;

		n = read(fd, buf + total, st.st_size - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;

			log_err("read failed for '%s': %s",
				path, strerror(errno));
			close(fd);
			return -errno;
		}

		if (n == 0)
			break;

		total += n;
	}

	close(fd);

	if (total != st.st_size) {
		log_err("short read from '%s': got=%zd expected=%lld",
			path, total, (long long)st.st_size);
		return -EIO;
	}

	*out_size = (uint32_t)total;
	return 0;
}

static int check_same_filesystem(int mount_fd,
				 int dir_fd,
				 const char *mountpoint,
				 const char *dirpath)
{
	struct stat mount_st;
	struct stat dir_st;

	if (fstat(mount_fd, &mount_st) < 0) {
		log_err("fstat failed for '%s': %s",
			mountpoint, strerror(errno));
		return -errno;
	}

	if (fstat(dir_fd, &dir_st) < 0) {
		log_err("fstat failed for '%s': %s",
			dirpath, strerror(errno));
		return -errno;
	}

	if (mount_st.st_dev != dir_st.st_dev) {
		log_err("directory '%s' is not on same filesystem as '%s'",
			dirpath, mountpoint);
		return -EXDEV;
	}

	return 0;
}

static int check_directory_empty(int dir_fd, const char *dirpath)
{
	struct dirent *de;
	DIR *dir;
	int dup_fd;
	int ret = 0;

	dup_fd = dup(dir_fd);
	if (dup_fd < 0) {
		log_err("dup failed for '%s': %s",
			dirpath, strerror(errno));
		return -errno;
	}

	dir = fdopendir(dup_fd);
	if (!dir) {
		log_err("fdopendir failed for '%s': %s",
			dirpath, strerror(errno));
		close(dup_fd);
		return -errno;
	}

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		log_err("directory '%s' must be empty before first-time fscrypt provisioning",
			dirpath);
		ret = -ENOTEMPTY;
		break;
	}

	closedir(dir);
	return ret;
}

static int add_key_from_blob(const struct options *opts,
			     int mount_fd,
			     uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	struct fspapp_fscrypt_add_key_arg *arg = NULL;
	int dev_fd = -1;
	int ret;

	arg = calloc(1, sizeof(*arg));
	if (!arg) {
		log_err("failed to allocate ioctl argument");
		return -ENOMEM;
	}

	arg->mount_fd = mount_fd;

	ret = read_wrapped_blob(opts->blob_path,
				arg->blob,
				sizeof(arg->blob),
				&arg->blob_size);
	if (ret)
		goto out;

	log_info(opts, "read wrapped blob '%s', size=%u",
		 opts->blob_path, arg->blob_size);

	dev_fd = open(opts->device_path, O_RDWR | O_CLOEXEC);
	if (dev_fd < 0) {
		log_err("failed to open device '%s': %s",
			opts->device_path, strerror(errno));
		ret = -errno;
		goto out;
	}

	log_info(opts, "sending wrapped blob to kernel driver '%s'",
		 opts->device_path);

	if (ioctl(dev_fd, FSPAPP_FSCRYPT_ADD_KEY_FROM_BLOB, arg) < 0) {
		log_err("ioctl FSPAPP_FSCRYPT_ADD_KEY_FROM_BLOB failed: %s",
			strerror(errno));
		ret = -errno;
		goto out;
	}

	memcpy(identifier, arg->identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
	ret = 0;

out:
	if (dev_fd >= 0)
		close(dev_fd);

	if (arg) {
		secure_memzero(arg, sizeof(*arg));
		free(arg);
	}

	return ret;
}

static int set_policy_v2(int dir_fd,
			 const char *dirpath,
			 const uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	struct fscrypt_policy_v2 policy;

	memset(&policy, 0, sizeof(policy));

	policy.version = FSCRYPT_POLICY_V2;
	policy.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
	policy.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
	policy.flags = FSCRYPT_POLICY_FLAGS_PAD_32;
	policy.log2_data_unit_size = 0;

	memcpy(policy.master_key_identifier,
	       identifier,
	       FSCRYPT_KEY_IDENTIFIER_SIZE);

	if (ioctl(dir_fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy) < 0) {
		log_err("FS_IOC_SET_ENCRYPTION_POLICY failed on '%s': %s",
			dirpath, strerror(errno));
		return -errno;
	}

	return 0;
}

static int apply_or_validate_policy_v2(int dir_fd,
				       const char *dirpath,
				       const uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	return set_policy_v2(dir_fd, dirpath, identifier);
}

int main(int argc, char **argv)
{
	struct options opts;
	uint8_t identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
	int mount_fd = -1;
	int dir_fd = -1;
	int ret;

	memset(identifier, 0, sizeof(identifier));

	ret = parse_options(argc, argv, &opts);
	if (ret == 1)
		return EXIT_SUCCESS;
	if (ret)
		return EXIT_FAILURE;

	mount_fd = open_directory(opts.mountpoint);
	if (mount_fd < 0)
		goto fail;

	ret = add_key_from_blob(&opts, mount_fd, identifier);
	if (ret)
		goto fail;

	printf("fscrypt key added successfully\n");
	printf("master_key_identifier: ");
	print_identifier(identifier);

	if (opts.action == ACTION_UNLOCK) {
		ret = EXIT_SUCCESS;
		goto out;
	}

	if (opts.action == ACTION_ENSURE) {
		ret = ensure_directory_exists(opts.dirpath);
		if (ret)
			goto fail;
	}

	dir_fd = open_directory(opts.dirpath);
	if (dir_fd < 0)
		goto fail;

	ret = check_same_filesystem(mount_fd, dir_fd,
				    opts.mountpoint, opts.dirpath);
	if (ret)
		goto fail;

	if (opts.action == ACTION_PROVISION) {
		ret = check_directory_empty(dir_fd, opts.dirpath);
		if (ret)
			goto fail;
	}

	ret = apply_or_validate_policy_v2(dir_fd, opts.dirpath, identifier);
	if (ret)
		goto fail;

	printf("FSCRYPT_POLICY_V2 applied or validated successfully on %s\n",
	       opts.dirpath);

	ret = EXIT_SUCCESS;
	goto out;

fail:
	ret = EXIT_FAILURE;

out:
	if (dir_fd >= 0)
		close(dir_fd);

	if (mount_fd >= 0)
		close(mount_fd);

	secure_memzero(identifier, sizeof(identifier));
	return ret;
}
