#ifndef LINK_SHM_H
#define LINK_SHM_H

#include <net/if.h>
#include <stdint.h>

#define LINK_SHM_MAGIC 0x4c534442u
#define LINK_SHM_VERSION 2u

#ifndef LINK_SHM_CAP
#define LINK_SHM_CAP 65536u
#endif

#define LINK_SHM_DEFAULT_NAME "lsdb_link_updates"
#define LINK_SHM_DEFAULT_PATH "/dev/shm/" LINK_SHM_DEFAULT_NAME

/*
 * Shared memory ring buffer for link updates.
 *
 * Intended model:
 * - single producer (middleware)
 * - single consumer (agent_netlink2)
 *
 * The producer writes a slot first, then publishes it by increasing write_pos.
 * The consumer advances read_pos after it has copied the slot out.
 * When write_pos - read_pos >= capacity, the producer should drop new updates
 * and increase producer_drops.
 */
struct link_shm_slot {
    char dev[IF_NAMESIZE];
    uint32_t src_ip_be;
    uint32_t loss;
    uint32_t delay_us;
    uint32_t jitter_us;
    uint32_t rate_mbit;
    uint32_t reserved_pad;
    uint64_t enqueue_ns;
};

struct link_shm_region {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t slot_size;

    uint64_t write_pos;
    uint64_t read_pos;
    uint64_t producer_drops;
    uint64_t consumer_bad;
    uint64_t consumer_heartbeat_ns;

    struct link_shm_slot slots[LINK_SHM_CAP];
};

#endif
