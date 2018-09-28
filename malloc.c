#include <stddef.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>

#define DBG_MAGIC  0xef0fe326

struct dbg_mem {
	unsigned magic;
 	void * ptr;
	size_t size;

	struct dbg_mem * next;
	struct dbg_mem * prev;

	const char * path;
	const char * func;
	unsigned line;
	struct timespec time;
};

struct dbg_ctx {
	int record;
	struct dbg_mem head;
	pthread_mutex_t mutex;
};

#define LIST_INSERT(p, l)	   \
	(l)->prev = (p);		   \
	(l)->next = (p)->next;	   \
	(p)->next->prev = (l);	   \
	(p)->next = (l)

#define LIST_REMOVE(l)							\
	(l)->prev->next = (l)->next;				\
	(l)->next->prev = (l)->prev

static int dbg_ctx_init(struct dbg_ctx * ctx);
static int dbg_dump();

#define dbg_printf(...)  \
	_tls_flag = 1;		 \
	libc_printf(__VA_ARGS__);\
	_tls_flag = 0
	

static void * libc_handle = NULL;
static void *(*libc_malloc)(size_t) = NULL;
static void  (*libc_free)(void *) = NULL;
static int (*libc_printf)(const char *, ...) = NULL;
static int (*libc_pthread_mutex_lock)(pthread_mutex_t *) = NULL;
static int (*libc_pthread_mutex_unlock)(pthread_mutex_t *) = NULL;
static int (*libc_pthread_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *) = NULL;
static int (*libc_clock_gettime)(clockid_t, struct timespec *);

unsigned mem_free = 0;
static int mem_dummy[4096*1024];

static __thread int _tls_flag = 0;

static struct dbg_ctx dbg_ctx = { 0 };

void * dbg_malloc(size_t size,
		const char *path, const char * func, int line)
{
	if (!libc_handle) {
		unsigned off = mem_free;
		mem_free += size;
		return (void *)&mem_dummy[off];
	}
	void * ptr = NULL;
	if (_tls_flag) {
		return libc_malloc(size);
	}

	ptr = libc_malloc(size + sizeof(struct dbg_mem));
	if (ptr) {
		struct dbg_mem * m = ptr;
		m->magic = DBG_MAGIC;
		m->ptr = ptr;
		m->size = size;
		m->path = path;
		m->func = func;
		m->line = line;

		libc_pthread_mutex_lock(&dbg_ctx.mutex);
		LIST_INSERT(&dbg_ctx.head, m);

		libc_clock_gettime(CLOCK_MONOTONIC, &m->time);
		ptr += sizeof(*m);
		libc_pthread_mutex_unlock(&dbg_ctx.mutex);

		dbg_printf("malloc: size = %d , ptr = %p \n", (int)size, ptr);
	}
	return ptr;
}

void dbg_free(void * ptr)
{
	if (ptr >= mem_dummy && ptr < (mem_dummy + mem_free)) {
		return;
	}
	if (libc_handle) {
		if (ptr) {
			dbg_printf("free: ptr = %p \n", ptr);
			if (1) { //!_tls_flag) {
				struct dbg_mem * m = (struct dbg_mem *)(ptr - sizeof(*m));
				if (m && m->magic == DBG_MAGIC && m->ptr == m) {
					libc_pthread_mutex_lock(&dbg_ctx.mutex);
					LIST_REMOVE(m);
					libc_pthread_mutex_unlock(&dbg_ctx.mutex);
					ptr -= sizeof(*m);
				}
			}
			libc_free(ptr);
		}
	}
}

void * malloc(size_t size)
{
	return dbg_malloc(size, NULL, NULL, -1);
}

void free(void *ptr)
{
	dbg_free(ptr);
}

static void dbg_init() __attribute__((constructor));
void
dbg_init()
{
	libc_handle = dlopen("libc.so.6", RTLD_NOW);

#define DL_FUNC(f) libc_##f = dlsym(libc_handle, #f)

	DL_FUNC(malloc);
	DL_FUNC(free);
	DL_FUNC(printf);
	DL_FUNC(pthread_mutex_init);
	DL_FUNC(pthread_mutex_lock);
	DL_FUNC(pthread_mutex_unlock);
	DL_FUNC(clock_gettime);

	dbg_ctx_init(&dbg_ctx);
}

static void dbg_fini() __attribute__((destructor));
void dbg_fini()
{
	dbg_dump();
}


static int
dbg_ctx_init(struct dbg_ctx * ctx)
{
	ctx->head.next = &ctx->head;
	ctx->head.prev = &ctx->head;
	libc_pthread_mutex_init(&ctx->mutex, NULL);

	//libc_printf("\ndbg_init done, memory dummy used %d\n", mem_free);
}

static int
dbg_dump()
{
	int r = 0;
	if (libc_handle) {
		libc_pthread_mutex_lock(&dbg_ctx.mutex);
		_tls_flag = 1;

		libc_printf("\ndbg_dump {\n");
		struct dbg_mem * m = dbg_ctx.head.next;
		while(m != &dbg_ctx.head) {
			libc_printf("\tmem %d: .size = %d, ptr = %p, time = { .sec=%x, .nsec=%x }\n",
					r, m->size, m->ptr, m->time.tv_sec, m->time.tv_nsec);
			r ++;
			m = m->next;
		}
		libc_printf("}\n");

		libc_pthread_mutex_unlock(&dbg_ctx.mutex);
		_tls_flag = 0;
	}
	return r;
}
