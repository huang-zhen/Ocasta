// versioning.c
// versioning misc utility functions

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif 
#include "versioning.h"

#define OFFSET(x,y) ((char *)&x.y - (char *)&x)
static int writebuffer(int file, const char* buffer, int len)
{
    int ret = 0;

    while (len > 0) {
	ret = write(file, buffer, len);
	if (ret <= 0) {
    		printf("%s: failed for %p (%d) -> %d\n", __FUNCTION__, buffer, len, ret);
		goto out;
	}
	len -= ret;
	buffer += ret;
    }
out:
    return ret;
}

static int readbuffer(int file, char *buffer, int len, int offset)
{
    int ret = 0;

    while (len > 0) {
	ret = pread(file, buffer, len, offset);
	if (ret < 0) {
    		printf("%s: failed %d\n", __FUNCTION__, ret);
		goto out;
	} else if (ret == 0)
		goto out;
	len -= ret;
	buffer += ret;
    }
out:
    return ret;
}
/*
 * Note that this routine will allocate memory for data and the caller is 
 * responsible to deallocate the memory
 * return code: 1	file undo data in pdata
 *		2	file was truncated to zero length
 *		0	version not found
 */
int find_version(const char *versionpath, int version, struct version_info *ver_inf, char **pdata)
{
    int fd;
    int ver = 0;
    int ret = 0;
    int offset = 0;

    if (version <= 0)
	goto out;
    fd = open(versionpath, O_RDONLY);
    if (fd < 0)
	goto out;
    for (ver = 0; ver < version; ver++) {
	if (readbuffer(fd, (char *)ver_inf, sizeof(struct version_info), offset) != sizeof(struct version_info))
		break;
	offset += sizeof(struct version_info);
    	if (ver == version - 1) {
    		if (ver_inf->size > 0) {
			if (pdata) {
			*pdata = (char *)malloc(ver_inf->size);
			if (*pdata != NULL && (readbuffer(fd, *pdata, ver_inf->size, offset) == ver_inf->size)) {
				//printf("%s: (%s) version info (%d) #%d-->offset:%ld, size:%d, extendseof:%d\n", __FUNCTION__, versionpath, sizeof(struct version_info), ver, ver_inf->offset, ver_inf->size, ver_inf->extendseof);
				offset += ver_inf->size;
				ret = 1;
			} else
				break;
			} else
				ret = 1;
    		} else if (ver_inf->size == 0 && ver_inf->extendseof)
			ret = 2;
		break;
    	} else {
		if (ver_inf->size > 0)
			offset += ver_inf->size;
	}
    }
    close(fd);
out:
    return ret;
}

int find_version_by_time(const char *versionpath, time_t time, struct version_info *ver_inf, char **pdata)
{
    int fd;
    int ret = 0;
    int offset = 0;

    fd = open(versionpath, O_RDONLY);
    if (fd < 0)
	goto out;
    for (;;) {
	if (readbuffer(fd, (char *)ver_inf, sizeof(struct version_info), offset) != sizeof(struct version_info))
		break;
	offset += sizeof(struct version_info);
    	if (ver_inf->timestamp >= time) {
    		if (ver_inf->size > 0) {
			*pdata = (char *)malloc(ver_inf->size);
			if (*pdata != NULL && (readbuffer(fd, *pdata, ver_inf->size, offset) == ver_inf->size)) {
				//printf("%s: (%s) version info (%d) #%d-->offset:%ld, size:%d, extendseof:%d\n", __FUNCTION__, versionpath, sizeof(struct version_info), ver, ver_inf->offset, ver_inf->size, ver_inf->extendseof);
				offset += ver_inf->size;
				ret = 1;
			} else
				break;
    		} else if (ver_inf->size == 0 && ver_inf->extendseof)
			ret = 2;
		break;
    	} else {
		if (ver_inf->size > 0)
			offset += ver_inf->size;
	}
    }
    close(fd);
out:
    return ret;
}

#define COPY_FILE_BUF_SIZE 512

int copy_file(const char *srcpath, const char *destpath)
{
    int srcfd, destfd, size;
    char buf[COPY_FILE_BUF_SIZE];
  
    //printf("%s: from %s to %s\n", __FUNCTION__, srcpath, destpath);
    srcfd = open(srcpath, O_RDONLY, 0600);
    if (srcfd < 0) {
	fprintf(stderr, "%s: unable to open %s\n", __FUNCTION__, srcpath);
	return 0;
    }
    destfd = open(destpath, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (destfd == -1) {
	fprintf(stderr, "%s: unable to create %s\n", __FUNCTION__, destpath);
	close(srcfd);
	return 0;
    }
    while (1) {
	size =  read(srcfd, buf, COPY_FILE_BUF_SIZE);
	if (size > 0) {
		if (write(destfd, buf, size) == -1) {
			printf("%s: write %d bytes failed\n", __FUNCTION__, size);
			break;
		}
	}
	else 
		break;
	if (size != COPY_FILE_BUF_SIZE)
		break;
    }
    close(srcfd);
    close(destfd);
    return 1;
}
    
/*
 * revert a version
 * returns 1 on success
 */
int revert_version(const char *path, const char *revertpath, int version)
{
    struct version_info ver_inf;
    int fd, ret = 0;
    char *data = NULL;
    char verpath[MAX_PATH];
    int found_version = 0;
    struct stat stbuf;
    int found_file = 1;

    if (stat(path, &stbuf)) {
	printf("Warnining: %s: does not exist.\n", path);
	found_file = 0;
	ret = mknod(path, 0666, 0);
	if (ret)
		printf("mknod %s failed %d\n", path, ret);
	else
		found_file = 1;
	//return 0;
    }
    strcpy(verpath, path);
    strcat(verpath, VERSIONMODIFIER);

    //printf("total:%d timestamp:%d offset:%d size:%d extendseof:%d\n", sizeof(ver_inf), OFFSET(ver_inf, timestamp), OFFSET(ver_inf, offset), OFFSET(ver_inf, size), OFFSET(ver_inf, extendseof));
    found_version = find_version(verpath, version, &ver_inf, &data);
    if (found_version) {
    	if (found_file && copy_file(path, revertpath)) {
	} else {
		printf("%s: copy_file %s -> %s faild\n", __FUNCTION__, path, revertpath);
		fd = open(revertpath, O_CREAT|O_TRUNC, 0600);
		close(fd);
	}
	{
		fd = open(revertpath, O_WRONLY, 0600);
		if (fd > 0) {
			if (found_version == 1) {
				if (pwrite(fd, data, ver_inf.size, ver_inf.offset) == ver_inf.size) {
					if (ver_inf.extendseof) {
						//printf("%s: truncate %s at %ld\n", __FUNCTION__, revertpath, ver_inf.offset + ver_inf.size);
						ftruncate(fd, ver_inf.offset + ver_inf.size);
					}
					ret = 1;
				} else
					printf("%s: write %s failed\n", __FUNCTION__, revertpath);
			} else if (found_version == 2) {
				ftruncate(fd, 0);
				ret = 1;
			}
			close(fd);
		} else
			printf("%s: open %s for write failed\n", __FUNCTION__, revertpath);
		free(data);
	}
    }
    return ret;
}

int revert_version_by_time(const char *path, const char *revertpath, time_t time)
{
    struct version_info ver_inf;
    int fd, ret = 0;
    char *data = NULL;
    char verpath[MAX_PATH];
    int found_version = 0;
    struct stat stbuf;

    if (stat(path, &stbuf)) {
	printf("%s: no such file.\n", path);
	return 0;
    }
    strcpy(verpath, path);
    strcat(verpath, VERSIONMODIFIER);

    found_version = find_version_by_time(verpath, time, &ver_inf, &data);
    if (found_version) {
    	if (copy_file(path, revertpath)) {
		fd = open(revertpath, O_WRONLY, 0600);
		if (fd > 0) {
			if (found_version == 1) {
				if (pwrite(fd, data, ver_inf.size, ver_inf.offset) == ver_inf.size) {
					if (ver_inf.extendseof) {
						//printf("%s: trunate %s at %ld\n", __FUNCTION__, revertpath, ver_inf.offset + ver_inf.size);
						ftruncate(fd, ver_inf.offset + ver_inf.size);
					}
					ret = 1;
				} else
					printf("%s: write %s failed\n", __FUNCTION__, revertpath);
			} else if (found_version == 2) {
				ftruncate(fd, 0);
				ret = 1;
			}
			close(fd);
		} else
			printf("%s: open %s for write failed\n", __FUNCTION__, revertpath);
		free(data);
	} else
		printf("%s: copy_file %s -> %s faild\n", __FUNCTION__, path, revertpath);
    }
    return ret;
}

/*
 * returns number of versions for a file
 */
int list_version(const char *path, int show_versions)
{
    struct version_info ver_inf;
    char verpath[MAX_PATH];
    int version = 1;
    int ret;
    struct stat stbuf;

    if (stat(path, &stbuf)) {
	printf("Warning: %s does not exist.\n", path);
	//return 0;
    }
    strcpy(verpath, path);
    strcat(verpath, VERSIONMODIFIER);

    //printf("total:%d timestamp:%d offset:%d size:%d extendseof:%d\n", sizeof(ver_inf), OFFSET(ver_inf, timestamp), OFFSET(ver_inf, offset), OFFSET(ver_inf, size), OFFSET(ver_inf, extendseof));

    ret = find_version(verpath, version, &ver_inf, NULL);
    if (ret <= 0)
	return 0;
    while (find_version(verpath, version, &ver_inf, NULL)) {
	if (!show_versions)
		printf("%d, %d, %d, %d, %d\n", version, (int)ver_inf.timestamp, (int)ver_inf.offset, ver_inf.size, ver_inf.extendseof);
	version ++;
    }
    if (show_versions)
	printf("%d\n", version - 1);
    return version - 1;
}

