#include "tc_offload.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "auxlib.h"
#include "call.h"
#include "log.h"
#include "main.h"
#include "media_socket.h"
#include "nft_rtpengine.h"

#include "ebpf/rtpengine_tc.h"

#if defined(HAVE_TC_OFFLOAD) && defined(__linux__)
#define RTPE_TC_IMPL 1
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

static bool tc_active;

#ifdef RTPE_TC_IMPL

/* Distinctive filter id so we do not collide with common handle=1 demos. */
#define RTPE_TC_HANDLE    0x72740001
#define RTPE_TC_PRIORITY  200

static struct bpf_object *tc_obj;
static int flows_fd = -1;
static GArray *attached_ifs;
static GHashTable *ifindex_cache; /* guint ipv4 -> gint ifindex */
static mutex_t ifindex_lock = MUTEX_STATIC_INIT;

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap) {
	if (level >= LIBBPF_DEBUG)
		return 0;
	char buf[512];
	vsnprintf(buf, sizeof(buf), fmt, ap);
	ilog(LOG_DEBUG, "libbpf: %s", buf);
	return 0;
}

static void re_to_tc_addr(struct rtpengine_tc_addr *o, const struct re_address *in) {
	memset(o, 0, sizeof(*o));
	if (in->family == AF_INET) {
		o->family = RTPENGINE_TC_AF_INET;
		o->port = htons(in->port);
		o->u.ipv4 = in->u.ipv4;
	}
	else if (in->family == AF_INET6) {
		o->family = RTPENGINE_TC_AF_INET6;
		o->port = htons(in->port);
		memcpy(o->u.ipv6, in->u.ipv6, 16);
	}
}

static void ep_to_re(struct re_address *o, const endpoint_t *ep) {
	memset(o, 0, sizeof(*o));
	if (!ep || !ep->address.family)
		return;
	ep->address.family->endpoint2kernel(o, ep);
}

static int ifindex_lookup_uncached(const struct re_address *local) {
	struct ifaddrs *ifa = NULL, *p;
	int idx = 0;

	if (getifaddrs(&ifa))
		return 0;
	for (p = ifa; p; p = p->ifa_next) {
		if (!p->ifa_addr || !p->ifa_name)
			continue;
		if (local->family == AF_INET && p->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *) p->ifa_addr;
			if (sin->sin_addr.s_addr == local->u.ipv4) {
				idx = if_nametoindex(p->ifa_name);
				break;
			}
		}
		else if (local->family == AF_INET6 && p->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) p->ifa_addr;
			if (!memcmp(&sin6->sin6_addr, local->u.ipv6, 16)) {
				idx = if_nametoindex(p->ifa_name);
				break;
			}
		}
	}
	freeifaddrs(ifa);
	return idx;
}

static int ifindex_for_addr(const struct re_address *local) {
	if (local->family != AF_INET)
		return ifindex_lookup_uncached(local);

	LOCK(&ifindex_lock);
	if (ifindex_cache) {
		gpointer cached = g_hash_table_lookup(ifindex_cache, GUINT_TO_POINTER(local->u.ipv4));
		if (cached) {
			int idx = GPOINTER_TO_INT(cached);
			return idx;
		}
	}

	int idx = ifindex_lookup_uncached(local);
	if (idx && ifindex_cache)
		g_hash_table_insert(ifindex_cache, GUINT_TO_POINTER(local->u.ipv4), GINT_TO_POINTER(idx));
	return idx;
}

static int attach_iface(const char *ifname) {
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		ilog(LOG_ERR, "TC offload: unknown interface '%s'", ifname);
		return -1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(tc_obj, "rtpengine_tc_ingress");
	if (!prog) {
		ilog(LOG_ERR, "TC offload: program rtpengine_tc_ingress not found");
		return -1;
	}

	LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_INGRESS,
	);
	int err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		ilog(LOG_ERR, "TC offload: bpf_tc_hook_create(%s): %s", ifname, strerror(-err));
		return -1;
	}

	LIBBPF_OPTS(bpf_tc_opts, opts,
		.handle = RTPE_TC_HANDLE,
		.priority = RTPE_TC_PRIORITY,
		.prog_fd = bpf_program__fd(prog),
	);
	err = bpf_tc_attach(&hook, &opts);
	if (err == -EEXIST) {
		/* Stale filter from a previous run — replace by detach + attach. */
		LIBBPF_OPTS(bpf_tc_opts, detach_opts,
			.handle = RTPE_TC_HANDLE,
			.priority = RTPE_TC_PRIORITY,
		);
		bpf_tc_detach(&hook, &detach_opts);
		err = bpf_tc_attach(&hook, &opts);
	}
	if (err) {
		ilog(LOG_ERR, "TC offload: bpf_tc_attach(%s): %s", ifname, strerror(-err));
		return -1;
	}

	g_array_append_val(attached_ifs, ifindex);
	ilog(LOG_INFO, "TC offload: attached on %s (ifindex %d)", ifname, ifindex);
	return 0;
}

static void detach_all(void) {
	if (!attached_ifs)
		return;
	for (guint i = 0; i < attached_ifs->len; i++) {
		int ifindex = g_array_index(attached_ifs, int, i);
		LIBBPF_OPTS(bpf_tc_hook, hook,
			.ifindex = ifindex,
			.attach_point = BPF_TC_INGRESS,
		);
		LIBBPF_OPTS(bpf_tc_opts, opts,
			.handle = RTPE_TC_HANDLE,
			.priority = RTPE_TC_PRIORITY,
		);
		/* Only detach our filter — do not destroy clsact (may be shared). */
		bpf_tc_detach(&hook, &opts);
	}
	g_array_set_size(attached_ifs, 0);
}

static const char *default_obj_path(void) {
	const char *env = getenv("RTPENGINE_TC_OFFLOAD_OBJ");
	if (env && env[0])
		return env;
	return "/usr/libexec/rtpengine/rtpengine_tc.bpf.o";
}

bool tc_offload_init(void) {
	if (!rtpe_config.tc_offload)
		return true;

	libbpf_set_print(libbpf_print);

	const char *path = default_obj_path();
	tc_obj = bpf_object__open_file(path, NULL);
	if (!tc_obj || libbpf_get_error(tc_obj)) {
		ilog(LOG_ERR, "TC offload: cannot open BPF object '%s': %s",
				path, strerror(errno));
		tc_obj = NULL;
		return false;
	}
	int err = bpf_object__load(tc_obj);
	if (err) {
		ilog(LOG_ERR, "TC offload: bpf_object__load: %s", strerror(-err));
		bpf_object__close(tc_obj);
		tc_obj = NULL;
		return false;
	}

	struct bpf_map *map = bpf_object__find_map_by_name(tc_obj, "flows");
	if (!map) {
		ilog(LOG_ERR, "TC offload: map 'flows' missing");
		bpf_object__close(tc_obj);
		tc_obj = NULL;
		return false;
	}
	flows_fd = bpf_map__fd(map);
	attached_ifs = g_array_new(false, false, sizeof(int));
	ifindex_cache = g_hash_table_new(g_direct_hash, g_direct_equal);

	if (!rtpe_config.tc_offload_interfaces || !rtpe_config.tc_offload_interfaces[0]) {
		ilog(LOG_ERR, "TC offload: --tc-offload-interfaces / "
				"RTPENGINE_TC_OFFLOAD_INTERFACES is required");
		tc_offload_shutdown();
		return false;
	}

	char **ifaces = g_strsplit_set(rtpe_config.tc_offload_interfaces, ", \t", -1);
	guint attached = 0;
	for (char **i = ifaces; i && *i; i++) {
		if (!**i)
			continue;
		if (attach_iface(*i)) {
			g_strfreev(ifaces);
			tc_offload_shutdown();
			return false;
		}
		attached++;
	}
	g_strfreev(ifaces);

	if (!attached) {
		ilog(LOG_ERR, "TC offload: no interfaces attached");
		tc_offload_shutdown();
		return false;
	}

	tc_active = true;
	ilog(LOG_INFO, "TC offload: active on %u interface(s)", attached);
	return true;
}

void tc_offload_shutdown(void) {
	detach_all();
	if (attached_ifs) {
		g_array_free(attached_ifs, true);
		attached_ifs = NULL;
	}
	{
		LOCK(&ifindex_lock);
		if (ifindex_cache) {
			g_hash_table_destroy(ifindex_cache);
			ifindex_cache = NULL;
		}
	}
	if (tc_obj) {
		bpf_object__close(tc_obj);
		tc_obj = NULL;
	}
	flows_fd = -1;
	tc_active = false;
}

static bool flow_is_plaintext(const struct rtpengine_srtp *dec, const struct rtpengine_srtp *enc) {
	if (!dec || !enc)
		return false;
	if (dec->cipher != REC_NULL || dec->hmac != REH_NULL)
		return false;
	if (enc->cipher != REC_NULL || enc->hmac != REH_NULL)
		return false;
	return true;
}

static void flush_flow_stats(struct packet_stream *stream, const struct rtpengine_tc_key *key) {
	struct rtpengine_tc_flow flow = {0};
	if (bpf_map_lookup_elem(flows_fd, key, &flow))
		return;
	if (!flow.packets && !flow.bytes)
		return;
	if (stream->stats_in) {
		atomic64_add_na(&stream->stats_in->packets, flow.packets);
		atomic64_add_na(&stream->stats_in->bytes, flow.bytes);
	}
	if (stream->selected_sfd && stream->selected_sfd->local_intf
			&& stream->selected_sfd->local_intf->stats) {
		atomic64_add_na(&stream->selected_sfd->local_intf->stats->in.packets, flow.packets);
		atomic64_add_na(&stream->selected_sfd->local_intf->stats->in.bytes, flow.bytes);
	}
}

bool tc_offload_add_stream(struct packet_stream *stream) {
	if (!tc_active || flows_fd < 0 || !stream || !stream->selected_sfd)
		return false;

	struct call_media *media = stream->media;
	if (!media || !proto_is_rtp(media->protocol))
		return false;
	if (MEDIA_ISSET(media, DTLS) || MEDIA_ISSET(media, ICE))
		return false;
	if (MEDIA_ISSET(media, BLACKHOLE) || MEDIA_ISSET(media, GENERATOR))
		return false;

	if (stream->rtp_sinks.length != 1)
		return false;
	struct sink_handler *sh = stream->rtp_sinks.head->data;
	if (!sh || sh->attrs.transcoding || sh->attrs.block_media)
		return false;
	struct packet_stream *sink = sh->bundle_sink ? sh->bundle_sink : sh->sink;
	if (!sink || !sink->selected_sfd || !PS_ISSET(sink, FILLED))
		return false;
	if (!sink->endpoint.address.family || !stream->endpoint.address.family)
		return false;

	const struct streamhandler *handler = determine_sink_handler(stream, sh);
	if (!handler || !handler->in->kernel || !handler->out->kernel)
		return false;

	struct rtpengine_srtp decrypt = {0}, encrypt = {0};
	if (handler->in->kernel(&decrypt, stream))
		return false;
	if (handler->out->kernel(&encrypt, sink))
		return false;
	if (!flow_is_plaintext(&decrypt, &encrypt))
		return false;

	struct re_address local = {0}, expected = {0}, src = {0}, dst = {0};
	ep_to_re(&local, &stream->selected_sfd->socket.local);
	ep_to_re(&expected, MEDIA_ISSET(media, ASYMMETRIC) ? &stream->learned_endpoint : &stream->endpoint);
	ep_to_re(&src, &sink->selected_sfd->socket.local);
	ep_to_re(&dst, &sink->endpoint);

	if (local.family != AF_INET || src.family != AF_INET || dst.family != AF_INET)
		return false;

	struct rtpengine_tc_key key = {0};
	struct rtpengine_tc_flow flow = {0};
	re_to_tc_addr(&key.local, &local);
	re_to_tc_addr(&flow.expected_src, &expected);
	re_to_tc_addr(&flow.src, &src);
	re_to_tc_addr(&flow.dst, &dst);
	if (expected.family == AF_INET && expected.port)
		flow.flags |= RTPENGINE_TC_F_CHECK_SRC;
	flow.ifindex = ifindex_for_addr(&src);
	if (!flow.ifindex) {
		ilog(LOG_WARNING, "TC offload: no ifindex for egress %s",
				endpoint_print_buf(&sink->selected_sfd->socket.local));
		return false;
	}

	if (bpf_map_update_elem(flows_fd, &key, &flow, BPF_ANY)) {
		ilog(LOG_WARNING, "TC offload: map update failed: %s", strerror(errno));
		return false;
	}

	ilog(LOG_INFO, "TC offload: installed %s -> %s (ifindex %u)",
			endpoint_print_buf(&stream->selected_sfd->socket.local),
			endpoint_print_buf(&sink->endpoint),
			flow.ifindex);
	return true;
}

void tc_offload_del_stream(struct packet_stream *stream) {
	if (!tc_active || flows_fd < 0 || !stream || !stream->selected_sfd)
		return;

	struct re_address local = {0};
	ep_to_re(&local, &stream->selected_sfd->socket.local);
	if (!local.family)
		return;

	struct rtpengine_tc_key key = {0};
	re_to_tc_addr(&key.local, &local);
	flush_flow_stats(stream, &key);
	bpf_map_delete_elem(flows_fd, &key);
	ilog(LOG_INFO, "TC offload: removed local %s",
			endpoint_print_buf(&stream->selected_sfd->socket.local));
}

#else

bool tc_offload_init(void) {
	if (!rtpe_config.tc_offload)
		return true;
	ilog(LOG_ERR, "TC offload requested but build lacks Linux/libbpf "
			"(rebuild with with_tc_offload=yes on Linux)");
	return false;
}

void tc_offload_shutdown(void) {
	tc_active = false;
}

bool tc_offload_add_stream(struct packet_stream *stream) {
	(void) stream;
	return false;
}

void tc_offload_del_stream(struct packet_stream *stream) {
	(void) stream;
}

#endif

bool tc_offload_wanted(void) {
	return rtpe_config.tc_offload;
}

bool tc_offload_is_active(void) {
	return tc_active;
}
