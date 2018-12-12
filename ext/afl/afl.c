#include <sys/shm.h>
#include <fcntl.h>

#include <ruby.h>
#include <ruby/st.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

// These need to be in sync with afl-fuzz
static const char* SHM_ENV_VAR = "__AFL_SHM_ID";
static const int FORKSRV_FD = 198;
#define MAP_SIZE_POW2 16
static const int MAP_SIZE = 1 << MAP_SIZE_POW2;
static unsigned char *afl_area = NULL;

static VALUE AFL = Qnil;
static VALUE init_done = Qfalse;

// #define log(...) snprintf(buf, sizeof(buf), __VA_ARGS__); write(logfd, buf, strlen(buf))
#define log(...)
int logfd;
char buf[128];

/**
 * Returns the location in the AFL shared memory to write the
 * given Ruby trace data to.
 *
 * Borrowed from afl-python for consistency
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
inline unsigned int lhash(const char *key, size_t offset) {
    size_t len = strlen(key);
    uint32_t h = 0x811C9DC5;
    while (len > 0) {
        h ^= (unsigned char) key[0];
        h *= 0x01000193;
        len -= 1;
        key += 1;
    }
    while (offset > 0) {
        h ^= (unsigned char) offset;
        h *= 0x01000193;
        offset >>= 8;
    }
    return h;
}

/**
 * Write Ruby trace data to AFL's shared memory.
 *
 * TODO: link to the AFL code that this is mimicing.
 */
VALUE afl_trace(VALUE _self, VALUE file_name, VALUE line_no) {
    static int prev_location;
    int offset;
    VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));

    if (init_done == Qfalse) {
        rb_raise(exc, "AFL not initialized, call ::AFL.init first!");
    }

    char* fname = StringValueCStr(file_name);
    size_t lno = FIX2INT(line_no);
    unsigned int location = lhash(fname, lno) % MAP_SIZE;
    log("[+] %s:%zu\n", fname, lno);

    offset = location ^ prev_location;
    prev_location = location / 2;
    log("[!] offset 0x%x\n", offset);
    afl_area[offset] += 1;

    log("[-] done with trace");
    return Qtrue;
}

/**
 * Initialize the AFL forksrv by testing that we can write to it.
 */
VALUE afl__init_forkserver(void) {
    log("Testing writing to forksrv fd=%d\n", FORKSRV_FD);

    int ret = write(FORKSRV_FD + 1, "\0\0\0\0", 4);
    if (ret != 4) {
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't write to forksrv");
    }

    log("Successfully wrote out nulls to forksrv ret=%d\n", ret);
    return Qnil;
}

VALUE afl__forkserver_read(VALUE _self) {
    unsigned int value;
    int ret = read(FORKSRV_FD, &value, 4);
    log("Read from forksrv value=%d ret=%d", value, ret);
    if (ret != 4) {
        log("Couldn't read from forksrv errno=%d", errno);
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't read from forksrv");
    }
    return INT2FIX(value);
}

/**
 * Write a value (generally a child_pid) to the AFL forkserver.
 */
VALUE afl__forkserver_write(VALUE _self, VALUE v) {
    unsigned int value = FIX2INT(v);

    int ret = write(FORKSRV_FD + 1, &value, 4);
    log("Wrote to forksrv_sock value=%d ret=%d\n", value, ret);
    if (ret != 4) {
        VALUE exc = rb_const_get(AFL, rb_intern("RuntimeError"));
        rb_raise(exc, "Couldn't write to forksrv");
    }
    return INT2FIX(ret);
}

/**
 *  Initialize AFL's shared memory segment.
 */
VALUE afl__init_shm(void) {
    log("Initializing SHM\n");
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
    log("afl_area at 0x%zx\n", afl_area);

    init_done = Qtrue;

    log("Done initializing SHM\n");
    return Qtrue;
}

/**
 * Close the AFL forksrv file descriptors.
 */
VALUE afl__close_forksrv_fds(VALUE _self) {
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);
    return Qnil;
}

VALUE afl_bail_bang(VALUE _self) {
    log("bailing\n");
    close(logfd);
    _exit(0);
}

void Init_afl(void);

void Init_afl(void) {
    AFL = rb_const_get(rb_cObject, rb_intern("AFL"));
    logfd = open("/tmp/aflog", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    log("...\n");

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
