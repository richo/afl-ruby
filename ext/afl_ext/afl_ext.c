#include <sys/shm.h>
#include <fcntl.h>

#include <ruby.h>
#include <ruby/st.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

// These need to be in sync with afl-fuzz
static const char* SHM_ENV_VAR = "__AFL_SHM_ID";
static const int FORKSRV_FD = 198;
#define MAP_SIZE_POW2 16
static const int MAP_SIZE = 1 << MAP_SIZE_POW2;
static unsigned char *afl_area = NULL;

static VALUE AFL = Qnil;
static VALUE init_done = Qfalse;

#ifdef AFL_RUBY_EXT_DEBUG_LOG
static FILE *aflogf = NULL;

static void aflogf_init(void) {
    int fd = open("/tmp/aflog",
            O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR);
    if (fd < 0) {
        fprintf(stderr, "unable to open() /tmp/aflog\n");
        _exit(1);
    }

    aflogf = fdopen(fd, "w");
    if (!aflogf) {
        fprintf(stderr, "unable to fdopen() /tmp/aflog\n");
        _exit(1);
    }
}

static void aflog_printf(const char *fmt, ...) {
    va_list ap;

    if (!aflogf) aflogf_init();

    va_start(ap, fmt);
    vfprintf(aflogf, fmt, ap);
    va_end(ap);

    // quiesce aflogf's writer buffer to disk immediately
    fflush(aflogf);
}

#define LOG aflog_printf
#else
#define LOG(...)
#endif

/**
 * Returns the location in the AFL shared memory to write the
 * given Ruby trace data to.
 *
 * Borrowed from afl-python for consistency, then refactored
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
#define LHASH_INIT       0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x)    h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline unsigned int lhash(const char *key, size_t offset) {
    const char *const last = &key[strlen(key) - 1];
    uint32_t h = LHASH_INIT;
    while (key <= last)               LHASH_NEXT(*key++);
    for (; offset != 0; offset >>= 8) LHASH_NEXT(offset);
    return h;
}

/**
 * Write Ruby trace data to AFL's shared memory.
 *
 * TODO: link to the AFL code that this is mimicking.
 */
static VALUE afl_trace(VALUE _self, VALUE file_name, VALUE line_no) {
    static int prev_location;
    int offset;
    VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));

    if (init_done == Qfalse) {
        rb_raise(exc, "AFL not initialized, call ::AFL.init first!");
    }

    char* fname = StringValueCStr(file_name);
    size_t lno = FIX2INT(line_no);
    unsigned int location = lhash(fname, lno) % MAP_SIZE;
    LOG("[+] %s:%zu\n", fname, lno);

    offset = location ^ prev_location;
    prev_location = location / 2;
    LOG("[!] offset 0x%x\n", offset);
    afl_area[offset] += 1;

    LOG("[-] done with trace");
    return Qtrue;
}

/**
 * Initialize the AFL forksrv by testing that we can write to it.
 */
static VALUE afl__init_forkserver(void) {
    LOG("Testing writing to forksrv fd=%d\n", FORKSRV_FD);

    int ret = write(FORKSRV_FD + 1, "\0\0\0\0", 4);
    if (ret != 4) {
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't write to forksrv");
    }

    LOG("Successfully wrote out nulls to forksrv ret=%d\n", ret);
    return Qnil;
}

static VALUE afl__forkserver_read(VALUE _self) {
    unsigned int value;
    int ret = read(FORKSRV_FD, &value, 4);
    LOG("Read from forksrv value=%d ret=%d", value, ret);
    if (ret != 4) {
        LOG("Couldn't read from forksrv errno=%d", errno);
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't read from forksrv");
    }
    return INT2FIX(value);
}

/**
 * Write a value (generally a child_pid) to the AFL forkserver.
 */
static VALUE afl__forkserver_write(VALUE _self, VALUE v) {
    unsigned int value = FIX2INT(v);

    int ret = write(FORKSRV_FD + 1, &value, 4);
    LOG("Wrote to forksrv_sock value=%d ret=%d\n", value, ret);
    if (ret != 4) {
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't write to forksrv");
    }
    return INT2FIX(ret);
}

/**
 *  Initialize AFL's shared memory segment.
 */
static VALUE afl__init_shm(void) {
    LOG("Initializing SHM\n");
    VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));

    if (init_done == Qtrue) {
        rb_raise(exc, "AFL already initialized");
    }

    const char * afl_shm_id_str = getenv(SHM_ENV_VAR);
    if (afl_shm_id_str == NULL) {
        rb_raise(
            exc,
            "No AFL SHM segment specified. AFL's SHM env var is not set."
            "Are we actually running inside AFL?");
    }

    const int afl_shm_id = atoi(afl_shm_id_str);
    afl_area = shmat(afl_shm_id, NULL, 0);
    if (afl_area == (void*) -1) {
        rb_raise(exc, "Couldn't map shm segment");
    }
    LOG("afl_area at 0x%zx\n", afl_area);

    init_done = Qtrue;

    LOG("Done initializing SHM\n");
    return Qtrue;
}

/**
 * Close the AFL forksrv file descriptors.
 */
static VALUE afl__close_forksrv_fds(VALUE _self) {
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);
    return Qnil;
}

static VALUE afl_bail_bang(VALUE _self) {
    LOG("bailing\n");
#ifdef AFL_RUBY_EXT_DEBUG_LOG
    if (aflogf) {
        fclose(aflogf);
        aflogf = NULL;
    }
#endif
    _exit(0);
}

void Init_afl_ext(void) {
    AFL = rb_const_get(rb_cObject, rb_intern("AFL"));
    rb_gc_register_mark_object(AFL);
    LOG("...\n");

    rb_define_module_function(AFL, "trace", afl_trace, 2);
    rb_define_module_function(AFL, "_init_shm", afl__init_shm, 0);
    rb_define_module_function(AFL, "_init_forkserver", afl__init_forkserver, 0);
    rb_define_module_function(AFL, "_close_forksrv_fds", afl__close_forksrv_fds, 0);
    rb_define_module_function(AFL, "_forkserver_read", afl__forkserver_read, 0);
    rb_define_module_function(AFL, "_forkserver_write", afl__forkserver_write, 1);
    rb_define_module_function(AFL, "bail!", afl_bail_bang, 0);
    VALUE vFORKSRV_FD = INT2FIX(FORKSRV_FD);
    rb_define_const(AFL, "FORKSRV_FD", vFORKSRV_FD);
}
