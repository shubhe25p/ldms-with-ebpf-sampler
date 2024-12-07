#define _GNU_SOURCE
#include <inttypes.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include "ldms.h"
#include "ldmsd.h"
#include "sampler_base.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <linux/types.h>

struct key_t {
    char fsname[32];
    __u64 bucket;
};

#define PIN_PATH "/sys/fs/bpf/fshist"

static ldms_set_t set = NULL;
static ldmsd_msg_log_f msglog;
#define SAMP "EBPF_SAMPLER"
static int metric_offset;
static base_data_t base;
struct metric_indices {
    char *key;
    int idx;
    struct metric_indices *next;  // or use a proper hashmap
};
static int map_fd;
static struct metric_indices *indices_head = NULL;
static int list_idx;
#define LBUFSZ 256
char* makeFS_BKT_KEY(struct key_t next_key){
			
			 int fslen = strlen(next_key.fsname);
			next_key.fsname[fslen] = '_';
			int rev=0, flag=0, bucket=next_key.bucket;
			if(bucket%10==0){
				flag=1;
			}
			while(bucket){
				int rem = bucket%10;
				rev = rev*10+rem;
				bucket = bucket/10;
			}
			bucket = rev;
			int i=fslen+1;
			while(bucket){
				int rem = bucket%10;
				next_key.fsname[i]=rem+'0';
				i++;
				bucket = bucket/10;
			}
			next_key.fsname[i] = '\0';
			if(flag){
				next_key.fsname[i]='0';
				next_key.fsname[i+1]='\0';
			}
			msglog(LDMSD_LDEBUG, SAMP ": make fs_key: %s\n", next_key.fsname);
			return next_key.fsname;
			
}

static int create_metric_set(base_data_t base)
{
    //create an ldms list with record and the only metric is count
	ldms_schema_t schema;
	int rc, i;
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
        msglog(LDMSD_LERROR,
		       "Failed to open pinned map: %s\n",PIN_PATH);
		goto err;
    }
	msglog(LDMSD_LDEBUG, SAMP ": map opened successfully\n");
	metric_offset = ldms_schema_metric_count_get(schema);

	// rc = ldms_schema_metric_add(schema, "FILESYSTEM", LDMS_V_U64);
	// if (rc < 0)
	// 	goto err;
	
	// rc = ldms_schema_metric_add(schema, "BUCKET", LDMS_V_U64);
	// if(rc < 0)
	// 	goto err;

	// rc = ldms_schema_metric_add(schema, "COUNT", LDMS_V_U64);
	// if(rc < 0)
	// 	goto err;
// Create record definition for filesystem metrics

// Populate record with metrics from eBPF map
__u64 value;
    int index;
    struct key_t key, next_key;
memset(&key, 0, sizeof(key));

//Loop through eBPF map to add metrics to record definition
while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
        char* fs_bkt_key = makeFS_BKT_KEY(next_key);
		
        // // Add metric to record definition - no unit needed for filesystem metrics
        index = ldms_schema_metric_add(schema, fs_bkt_key, LDMS_V_U64);
		
		struct metric_indices *new_index = malloc(sizeof(struct metric_indices));
        new_index->key = strdup(fs_bkt_key);  // Make a copy of the key
        new_index->idx = index;
        new_index->next = indices_head;
        indices_head = new_index;
		msglog(LDMSD_LDEBUG, SAMP ": linked list node created for: %s with index %d\n", new_index->key, new_index->idx);
    }
    key = next_key;
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
static int config_check(struct attr_value_list *kwl, struct attr_value_list *avl, void *arg)
{
	char *value;
	int i;

	char* deprecated[]={"set"};

	for (i = 0; i < (sizeof(deprecated)/sizeof(deprecated[0])); i++){
		value = av_value(avl, deprecated[i]);
		if (value){
			msglog(LDMSD_LERROR, SAMP ": config argument %s has been deprecated.\n",
			       deprecated[i]);
			return EINVAL;
		}
	}

	return 0;
}

static const char *usage(struct ldmsd_plugin *self)
{
	return  "config name=" SAMP " " BASE_CONFIG_USAGE;
}

static int config(struct ldmsd_plugin *self, struct attr_value_list *kwl, struct attr_value_list *avl)
{
	int rc;

	if (set) {
		msglog(LDMSD_LERROR, SAMP ": Set already created.\n");
		return EINVAL;
	}

	rc = config_check(kwl, avl, NULL);
	if (rc != 0){
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

static ldms_set_t get_set(struct ldmsd_sampler *self)
{
	return set;
}
static int sample(struct ldmsd_sampler *self)
{
    // for each sample, adjust records and store count metric, dont know if atomics needed? 
	int rc;
	int metric_no;
	char *s;
	char metric_name[LBUFSZ];
	union ldms_value v;
    __u64 value;
    int index;
    struct key_t key, next_key;
	/*
			here in the sample search for the metric
			in the record and if found, update the value for it
			if not found then resize set and allocate new space 
			for a new record and append it, everything in a transaction	
	 */
    if (!set) {
		msglog(LDMSD_LDEBUG, SAMP ": plugin not initialized\n");
		return EINVAL;
	}

    base_sample_begin(base);
	metric_no = metric_offset;

    ldms_transaction_begin(set);

        memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {

            //  index = ldms_metric_by_name(set, "FILESYSTEM");
            //  ldms_metric_array_set_str(set, index, next_key.fsname);
            //  index = ldms_metric_by_name(set, "BUCKET");
            //  ldms_metric_set_u64(set, index, next_key.bucket);
            //  index = ldms_metric_by_name(set, "COUNT");
            //  ldms_metric_set_u64(set, index, value);
			
			 //char* temp = makeFS_BKT_KEY(next_key);
char* fs_bkt_key = makeFS_BKT_KEY(next_key);
// // // Find the stored index for this key
struct metric_indices *current = indices_head;
while (current) {
    if (strcmp(current->key, fs_bkt_key) == 0) {
		v.v_u64 = value;
        ldms_metric_set(set, current->idx, &v);
msglog(LDMSD_LDEBUG, SAMP ": filesystem_bkt: %s -- count  %d\n", fs_bkt_key, value);
        break;
    }
    current = current->next;
}
// free(fs_bkt_key);

        }
        key = next_key;
    }
    ldms_transaction_end(set);
    rc = 0;
	base_sample_end(base);
	return rc;

}

static void term(struct ldmsd_plugin *self)
{
	if (map_fd)
		close(map_fd);
	map_fd = 0;
	if (base)
		base_del(base);
	if (set)
		ldms_set_delete(set);
	set = NULL;
}

static struct ldmsd_sampler ebpf_plugin = {
	.base = {
		.name = SAMP,
		.type = LDMSD_PLUGIN_SAMPLER,
		.term = term,
		.config = config,
		.usage = usage
	},
	.get_set = get_set,
	.sample = sample,
};

struct ldmsd_plugin *get_plugin(ldmsd_msg_log_f pf)
{
	msglog = pf;
	set = NULL;
	return &ebpf_plugin.base;
}