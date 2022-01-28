/*
 * Copyright: Björn Ståhl
 * License: 3-Clause BSD, see COPYING file in arcan source repository.
 * Reference: http://arcan-fe.com
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <arcan_math.h>
#include <arcan_general.h>
#include <arcan_db.h>

static struct {
	union {
		struct {
			char* appl;
			char* shared;
			char* temp;
			char* state;
			char* appbase;
			char* appstore;
			char* statebase;
			char* font;
			char* bins;
			char* libs;
			char* debug;
			char* sysscr;
		};
		char* paths[12];
	};

	int flags[12];
	int lenv[12];

} namespaces = {0};

static const char* lbls[] = {
	"application",
	"application-shared",
	"application-temporary",
	"application-state",
	"system-applbase",
	"system-applstore",
	"system-statebase",
	"system-font",
	"system-binaries",
	"system-libraries",
	"system-debugoutput",
	"system-scripts"
};

static unsigned i_log2(uint32_t n)
{
	unsigned res = 0;
	while (n >>= 1) res++;
	return res;
}

char* arcan_find_resource(const char* label,
	enum arcan_namespaces space, enum resource_type ares)
{
	if (label == NULL || verify_traverse(label) == NULL)
		return NULL;

	space &= ~RESOURCE_NS_USER;
	size_t label_len = strlen(label);

	for (int i = 1, j = 0; i <= RESOURCE_SYS_ENDM; i <<= 1, j++){
		if ((space & i) == 0 || !namespaces.paths[j])
			continue;

		char scratch[ namespaces.lenv[j] + label_len + 2 ];
		snprintf(scratch, sizeof(scratch),
			label[0] == '/' ? "%s%s" : "%s/%s",
			namespaces.paths[j], label
		);

		if (
			((ares & ARES_FILE) && arcan_isfile(scratch)) ||
			((ares & ARES_FOLDER) && arcan_isdir(scratch))
		)
			return strdup(scratch);
	}

	return NULL;
}

char* arcan_fetch_namespace(enum arcan_namespaces space)
{
	space &= ~RESOURCE_NS_USER;
	int space_ind = i_log2(space);
	assert(space > 0 && (space & (space - 1) ) == 0);
	if (space_ind > sizeof(namespaces.paths)/sizeof(namespaces.paths[0]))
		return NULL;
	return namespaces.paths[space_ind];
}

char* arcan_expand_resource(const char* label, enum arcan_namespaces space)
{
	assert( space > 0 && (space & (space - 1) ) == 0 );
	space &= ~RESOURCE_NS_USER;

	int space_ind =i_log2(space);
	if (space_ind > sizeof(namespaces.paths)/sizeof(namespaces.paths[0]) ||
		label == NULL || verify_traverse(label) == NULL ||
		!namespaces.paths[space_ind]
	)
		return NULL;

	size_t len_1 = strlen(label);
	size_t len_2 = namespaces.lenv[space_ind];

	if (len_1 == 0)
		return namespaces.paths[space_ind] ?
			strdup( namespaces.paths[space_ind] ) : NULL;

	char cbuf[ len_1 + len_2 + 2 ];
	memcpy(cbuf, namespaces.paths[space_ind], len_2);
	cbuf[len_2] = '/';
	memcpy(&cbuf[len_2 + (label[0] == '/' ? 0 : 1)], label, len_1+1);

	return strdup(cbuf);
}

static char* atypestr = NULL;
const char* arcan_frameserver_atypes()
{
	return atypestr ? atypestr : "";
}

bool arcan_verify_namespaces(bool report)
{
	bool working = true;

	if (report)
		arcan_warning("--- Verifying Namespaces: ---\n");

/* 1. check namespace mapping for holes */
	for (int i = 0; i < sizeof(
		namespaces.paths) / sizeof(namespaces.paths[0]); i++){
			if (namespaces.paths[i] == NULL){
				if (i != (int)log2(RESOURCE_SYS_LIBS)){
					working = false;
					if (report)
						arcan_warning("%s -- broken\n", lbls[i]);
					continue;
				}
			}

		if (report)
			arcan_warning("%s -- OK (%s)\n", lbls[i], namespaces.paths[i]);
	}

	if (report)
		arcan_warning("--- Namespace Verification Completed ---\n");

/* 2. missing; check permissions for each mounted space, i.e. we should be able
 * to write to state, we should be able to write to appl temporary etc.  also
 * check disk space for possible warning conditions (these should likely also
 * be emitted as system events)
 */

	if (working){
		char* toktmp = strdup(FRAMESERVER_MODESTRING);

/* modestring is static, atypestr can only be reduced in bytes used */
		if (!atypestr)
			atypestr = strdup(FRAMESERVER_MODESTRING);

		char* tokctx, (* tok) = strtok_r(toktmp, " ", &tokctx);
		if (tok && atypestr){
			char* base = arcan_expand_resource("", RESOURCE_SYS_BINS);
			size_t baselen = strlen(base);

/* fix for specialized "do we have default arcan_frameserver? then compact to
 * afsrv_ for archetype prefix" mode */
			size_t sfxlen = sizeof("arcan_frameserver") - 1;
			if (baselen >= sfxlen){
				if (strcmp(&base[baselen - sfxlen], "arcan_frameserver") == 0){
					const char* sfx = "afsrv";
					memcpy(&base[baselen - sfxlen], sfx, sizeof("afsrv"));
				}
			}

/* could / should do a more rigorous test of the corresponding afsrv, e.g.
 * executable, permission and linked shmif version */
			atypestr[0] = '\0';
			bool first = true;
			do{
				char* fn;
				char exp[2 + baselen + strlen(tok)];
				snprintf(exp, sizeof(exp), "%s_%s", base, tok);
				if (arcan_isfile(exp)){
					if (!first){
						strcat(atypestr, " ");
					}
					strcat(atypestr, tok);
					first = false;
				}
			} while ((tok = strtok_r(NULL, " ", &tokctx)));

			free(base);
		}
		free(toktmp);
	}

	return working;
}

void arcan_softoverride_namespace(const char* new, enum arcan_namespaces space)
{
	char* tmp = arcan_expand_resource("", space);
	if (!tmp)
		arcan_override_namespace(new, space);
	else
		free(tmp);
}

void arcan_pin_namespace(enum arcan_namespaces space)
{
	space &= ~RESOURCE_NS_USER;
	int ind = i_log2(space);
	namespaces.flags[ind] = 1;
}

void arcan_override_namespace(const char* path, enum arcan_namespaces space)
{
	if (path == NULL)
		return;

	space &= ~RESOURCE_NS_USER;
	assert( space > 0 && (space & (space - 1) ) == 0 );
	int space_ind =i_log2(space);

	if (namespaces.paths[space_ind] != NULL){
		if (namespaces.flags[space_ind])
			return;

		arcan_mem_free(namespaces.paths[space_ind]);
	}

	namespaces.paths[space_ind] = strdup(path);
	namespaces.lenv[space_ind] = strlen(namespaces.paths[space_ind]);
}

/* take a properly formatted namespace string (label:perm:path)
 * and split up into the arcan_userns structure */
static bool decompose(char* ns, struct arcan_userns* dst)
{
	char* tmp = ns;
	size_t pos = 0;
	while (tmp){
		char* cur = strsep(&tmp, ":");
		switch(pos){
			case 0: snprintf(dst->label, 64, "%s", cur); break;
			case 1:
				if (strcmp(cur, "r") == 0)
					dst->perm = O_RDONLY;
				else if (strcmp(cur, "w") == 0)
					dst->perm = O_WRONLY;
				else if (strcmp(cur, "rw") == 0)
					dst->perm = O_RDWR;
				else
					return false;
			case 2:
				return true;
			break;
		}
		pos++;
	}
	return false;
}

struct arcan_strarr arcan_user_namespaces()
{
	struct arcan_strarr list =
		arcan_db_applkeys(arcan_db_get_shared(NULL), "arcan", "ns_%");

	if (!list.data)
		return list;

	struct arcan_strarr res = {0};

	char** curr = res.data;
	while (curr && *curr){
		struct arcan_userns ns;
		if (!decompose(*curr++, &ns))
			continue;

		if (res.count == res.limit){
			arcan_mem_growarr(&res);
			if (res.count == res.limit)
				goto out;
		}

		struct arcan_userns* newns = malloc(sizeof(newns));
		if (newns){
			*newns = ns;
			res.cdata[res.count++] = newns;
		}
	}

out:
	arcan_mem_freearr(&list);
	return res;
}

bool arcan_lookup_namespace(const char* id, struct arcan_userns* dst, bool dfd)
{
	size_t len = strlen(id) + sizeof("ns_");
	char* buf = malloc(len);
	snprintf(buf, len, "ns_%s", id);

	struct arcan_strarr res = arcan_db_applkeys(arcan_db_get_shared(NULL), "arcan", buf);

/* for each entry, check validity (rw: w: r: id :label:path */

	arcan_mem_freearr(&res);
	return false;
}

