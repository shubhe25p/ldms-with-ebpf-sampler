#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <inttypes.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ldms.h"
#include "ldmsd.h"
#include "sampler_base.h"

struct key_t {
    __u64 bucket;
    __u64 ts;
    __u64 delta_us;
    __u64 throughput;
    __u32 pid;
    __u32 sz;
    char fstype[16]; /* arbitrary choice for file system type, no fs would have this greater than 16 chars */
    char msrc[16];   /* arbitrary choice for mount-source, makes no sense */
    char name[32];
    char comm[16];
};

#define PIN_PATH "/sys/fs/bpf/fshist"
#define SAMP "EBPF_SAMPLER"

static ldms_set_t set = NULL;
static ldmsd_msg_log_f msglog;
static int metric_offset;
static base_data_t base;
struct metric_info {
        struct key_t key;
        int idx;
};

static int map_fd;
static struct metric_info *metrics = NULL;
static int list_idx;
static size_t metric_cnt = 0;
#define LBUFSZ 256

char *make_key(struct key_t *k) {
        char *name = malloc(80);
        if (!name) return NULL;
        snprintf(name, 80, "fs_%s_bkt%llu", k->msrc, k->bucket);
        return name;
}

static int create_metric_set(base_data_t base) {
        // create an ldms list with record and the only metric is count
        ldms_schema_t schema;
        int rc;
        uint64_t metric_value;
        char *s;
        char lbuf[LBUFSZ];
        char metric_name[LBUFSZ];

        schema = base_schema_new(base);
        if (!schema) {
                msglog(LDMSD_LERROR,
                       "%s: The schema '%s' could not be created, errno=%d.\n",
                       __FILE__, base->schema_name, errno);
                rc = errno;
                goto err;
        }
        map_fd = bpf_obj_get(PIN_PATH);
        if (map_fd < 0) {
                msglog(LDMSD_LERROR, "Failed to open pinned map: %s\n",
                       PIN_PATH);
                goto err;
        }
        msglog(LDMSD_LDEBUG, SAMP ": map opened successfully\n");
        metric_offset = ldms_schema_metric_count_get(schema);
        __u64 value;
        int index;
        struct key_t cur = {0}, next;
        while (bpf_map_get_next_key(map_fd, &cur, &next) == 0) {
                metric_cnt++;
                cur = next;
        }
        msglog(LDMSD_LDEBUG, SAMP "Total number of metrics: %d\n", metric_cnt);
        if (metric_cnt == 0) return ENOENT;

        /* Allocate cache */
        metrics = calloc(metric_cnt, sizeof(*metrics));
        if (!metrics) return ENOMEM;

        size_t i = 0;
        memset(&cur, 0, sizeof(cur));
        while (bpf_map_get_next_key(map_fd, &cur, &next) == 0) {
                if (bpf_map_lookup_elem(map_fd, &next, &value) == 0) {
                        char *mname = make_key(&next);
                        msglog(LDMSD_LDEBUG, SAMP "Key created %s\n", mname);
                        int midx =
                            ldms_schema_metric_add(schema, mname, LDMS_V_U64);
                        free(mname);
                        if (midx < 0) return midx;
                        metrics[i].key = next;
                        metrics[i].idx = midx;
                        i++;
                        cur = next;
                }
        }
        set = base_set_new(base);
        if (!set) {
                rc = errno;
                goto err;
        }
        return 0;

err:

        base_schema_delete(base);
        return rc;
}

/**
 * check for invalid flags, with particular emphasis on warning the user about
 */
static int config_check(struct attr_value_list *kwl,
                        struct attr_value_list *avl, void *arg) {
        char *value;
        int i;

        char *deprecated[] = {"set"};

        for (i = 0; i < (sizeof(deprecated) / sizeof(deprecated[0])); i++) {
                value = av_value(avl, deprecated[i]);
                if (value) {
                        msglog(LDMSD_LERROR,
                               SAMP
                               ": config argument %s has been deprecated.\n",
                               deprecated[i]);
                        return EINVAL;
                }
        }

        return 0;
}

static const char *usage(struct ldmsd_plugin *self) {
        return "config name=" SAMP " " BASE_CONFIG_USAGE;
}

static int config(struct ldmsd_plugin *self, struct attr_value_list *kwl,
                  struct attr_value_list *avl) {
        int rc;

        if (set) {
                msglog(LDMSD_LERROR, SAMP ": Set already created.\n");
                return EINVAL;
        }

        rc = config_check(kwl, avl, NULL);
        if (rc != 0) {
                return rc;
        }

        base = base_config(avl, SAMP, SAMP, msglog);
        if (!base) {
                rc = errno;
                goto err;
        }

        rc = create_metric_set(base);
        if (rc) {
                msglog(LDMSD_LERROR, SAMP ": failed to create a metric set.\n");
                goto err;
        }
        return 0;
err:
        base_del(base);
        return rc;
}

static ldms_set_t get_set(struct ldmsd_sampler *self) { return set; }

static int sample(struct ldmsd_sampler *self) {
        // for each sample, adjust records and store count metric, dont know if
        // atomics needed?

        if (!set) {
                msglog(LDMSD_LDEBUG, SAMP ": plugin not initialized\n");
                return EINVAL;
        }
        base_sample_begin(base);

        ldms_transaction_begin(set);
        for (size_t i = 0; i < metric_cnt; i++) {
                __u64 val = 0;
                if (bpf_map_lookup_elem(map_fd, &metrics[i].key, &val) == 0) {
                        union ldms_value v = {.v_u64 = val};
                        ldms_metric_set(set, metrics[i].idx, &v);
                }
        }
        ldms_transaction_end(set);
        int rc = 0;
        base_sample_end(base);
        return rc;
}

static void term(struct ldmsd_plugin *self) {
        if (map_fd) close(map_fd);
        map_fd = 0;
        free(metrics);
        metrics = NULL;
        metric_cnt = 0;
        if (base) base_del(base);
        if (set) ldms_set_delete(set);
        set = NULL;
}

static struct ldmsd_sampler ebpf_plugin = {
    .base = {.name = SAMP,
             .type = LDMSD_PLUGIN_SAMPLER,
             .term = term,
             .config = config,
             .usage = usage},
    .get_set = get_set,
    .sample = sample,
};

struct ldmsd_plugin *get_plugin(ldmsd_msg_log_f pf) {
        msglog = pf;
        set = NULL;
        return &ebpf_plugin.base;
}
