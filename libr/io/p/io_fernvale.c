/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_hash.h>
#include <r_lib.h>

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define FV_FILE "/dev/mem"
#define FV_SIZE 0xffff

typedef struct r_io_fernvale_t {
	char *filename;
	int mode;
	int flags;
	int fd;
	ut16 *words;
	ut8 backbuffer[FV_SIZE];
	RIO * io_backref;
} RIOFernvale;

static void r_io_fernvale_free(RIOFernvale *fv) {
	if (fv->words)
		munmap(fv->words, FV_SIZE);
	if (fv->fd && fv->fd != -1)
		close(fv->fd);
	free(fv->filename);
	memset(fv, 0, sizeof (RIOFernvale));
	free(fv);
}

static int r_io_fernvale_close(RIODesc *fd) {
	if (!fd || !fd->data)
		return -1;
	r_io_fernvale_free((RIOFernvale *) fd->data);
	fd->data = NULL;
	return 0;
}

static int r_io_fernvale_check(const char *filename) {
	if (filename && !strncmp(filename, "fv://", 5))
		return 1;
	return 0;
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return r_io_fernvale_check(file);
}

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
	RIOFernvale *fv;
	if (!r_io_fernvale_check(file))
		return NULL;

	if (!io)
		return NULL;

	fv = R_NEW0(RIOFernvale);
	if (!fv)
		return NULL;

	fv->filename = strdup(file);
	fv->mode = mode;
	fv->flags = flags;
	fv->io_backref = io;
	fv->fd = open(FV_FILE, O_RDWR);

	if (fv->fd == -1) {
		eprintf("io_fernvale: unable to open " FV_FILE "\n");
		r_io_fernvale_free(fv);
		return NULL;
	}

	fv->words = (ut16 *)mmap(NULL, FV_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, fv->fd, 0x08010000);
	if (fv->words == (ut16 *)-1) {
		eprintf("io_fernvale: unable to mmap /dev/mem\n");
		fv->words = NULL;
		r_io_fernvale_free(fv);
		return NULL;
	}

	int i;
	ut16 *bb_ptr = (ut16 *)fv->backbuffer;
	/* Create a backbuffer so we can do 32-bit SHA1 sums */
	for (i = 0; i < FV_SIZE / 2; i++)
		bb_ptr[i] = fv->words[i];

	return r_io_desc_new(&r_io_plugin_fernvale, fv->fd,
				fv->filename, flags, mode, fv);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	RIOFernvale *fv = NULL;
	ut16 *buf16 = (ut16 *)buf;
	int len_orig = len;

	if (!fd || !fd->data || !buf)
		return -1;
	fv = fd->data;

	if (io->off > FV_SIZE)
		return -1;

	if (io->off + len > FV_SIZE) {
		len = FV_SIZE - io->off;
		len_orig = len;
	}

	/* Take care of off-by-one at the start */
	if (io->off & 1) {
		buf[0] = fv->words[io->off / 2] >> 8;
		io->off++;
		buf++;
		len--;
		buf16 = (ut16 *)buf;
	}

	while (len > 1) {
		*buf16++ = fv->words[io->off / 2];
		len -= 2;
		io->off += 2;
	}

	/* Take care of off-by-one at the end */
	if (len == 1) {
		((ut8 *)buf16)[0] = fv->words[io->off / 2] & 0xff;
		io->off++;
		buf++;
		len--;
		buf16 = (ut16 *)buf;
	}
	return len_orig;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	RIOFernvale *fv;
	const ut16 *buf16 = (const ut16 *)buf;
	int len_orig = len;
	int do_sha1_1bl;

	fv = fd->data;

	if (io->off > FV_SIZE)
		return -1;

	if (io->off + len > FV_SIZE) {
		len = FV_SIZE - io->off;
		len_orig = len;
	}

	/* XXX Hack: Always do SHA1 sums (even though we might not have to) */
	do_sha1_1bl = 1;

	/* Workaround to make SHA sums faster */
	memcpy(fv->backbuffer + io->off, buf, len);

	/* Take care of off-by-one at the start */
	if (io->off & 1) {
		ut8 prev;
		ut16 n;
		prev = (fv->words[io->off / 2] & 0xff);
		n = (prev << 0) | (buf[0] << 8);
		fv->words[io->off / 2] = n;
		io->off++;
		buf++;
		len--;
		buf16 = (const ut16 *)buf;
	}

	while (len > 1) {
		fv->words[io->off / 2] = *buf16++;
		len -= 2;
		io->off += 2;
	}

	/* Take care of off-by-one at the end */
	if (len == 1) {
		ut8 prev;
		ut16 n;
		prev = (fv->words[io->off / 2] & 0xff00) >> 8;
		n = ((prev << 8) & 0xff00) | ((((ut8 *)buf16)[0] << 0) & 0x00ff);
		fv->words[io->off / 2] = n;

		io->off++;
		buf++;
		len--;
		buf16 = (const ut16 *)buf;
	}

	/* Update the SHA1 sum, if necessary */
	if (do_sha1_1bl) {
		RHash *h = r_hash_new(R_TRUE, R_HASH_SHA1);
		const ut8 *c = r_hash_do_sha1(h, fv->backbuffer + 0x800, 0x28f4 - 0x800);
		int i;
		for (i = 0; i < 10; i++) {
			fv->words[(0x28f4 / 2) + i] = (c[i * 2] << 0) | (c[i * 2 + 1] << 8);
		}
		r_hash_free(h);
	}

	return len_orig;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
		case SEEK_SET: return offset;
		case SEEK_CUR: return io->off + offset;
		case SEEK_END: return FV_SIZE;
	}
	return offset;
}

static int __close(RIODesc *fd) {
	return r_io_fernvale_close(fd);
}

static int __resize(RIO *io, RIODesc *fd, ut64 size) {
	return -1;
}

struct r_io_plugin_t r_io_plugin_fernvale = {
	.name = "fernvale",
	.desc = "open file using fv://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_fernvale
};
#endif
