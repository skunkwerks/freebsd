/*-
 * Copyright (c) 2023, 2024 Dave Cottlehuber <dch@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* #include <sys/cdefs.h> */

#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fetch.h>

#include <lua.h>
#include "lauxlib.h"
#include "lfetch.h"

#define CHUNK_SIZE 4096
#define MAX_HEADERS 32

/*
 * Minimal implementation of libfetch
 */

/* Helper function to build headers string from Lua table */
static char *
build_headers(lua_State *L, int index)
{
    char *headers = NULL;
    size_t total_len = 0;
    size_t header_count = 0;

    if (!lua_istable(L, index)) {
        return strdup("");
    }

    /* First pass: calculate total length needed */
    lua_pushnil(L);
    while (lua_next(L, index) != 0 && header_count < MAX_HEADERS) {
        const char *key = lua_tostring(L, -2);
        const char *value = lua_tostring(L, -1);
        if (key && value) {
            total_len += strlen(key) + strlen(value) + 4; /* key: value\n\0 */
            header_count++;
        }
        lua_pop(L, 1);
    }

    if (total_len == 0) {
        return strdup("");
    }

    headers = malloc(total_len);
    if (headers == NULL) {
        return NULL;
    }
    headers[0] = '\0';

    /* Second pass: build headers string */
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        const char *key = lua_tostring(L, -2);
        const char *value = lua_tostring(L, -1);
        if (key && value) {
            strcat(headers, key);
            strcat(headers, ": ");
            strcat(headers, value);
            strcat(headers, "\n");
        }
        lua_pop(L, 1);
    }

    return headers;
}

static int
lfetch_parse_url(lua_State *L)
{
	const char *url = luaL_checkstring(L, 1);
	struct url *u;

	u = fetchParseURL(url);
	if (u == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to parse URL");
		return (2);
	}

	lua_newtable(L);
	lua_pushstring(L, u->scheme);
	lua_setfield(L, -2, "scheme");
	lua_pushstring(L, u->user);
	lua_setfield(L, -2, "user");
	lua_pushstring(L, u->pwd);
	lua_setfield(L, -2, "password");
	lua_pushstring(L, u->host);
	lua_setfield(L, -2, "host");
	/* if port is not explicitly set, it defaults to 0, not scheme */
	if (u->port != 0) {
        lua_pushinteger(L, u->port);
    } else {
        lua_pushnil(L);
    }
	lua_setfield(L, -2, "port");
	/* for http(s), doc is the combined path & query string */
	lua_pushstring(L, u->doc);
	lua_setfield(L, -2, "doc");
	fetchFreeURL(u);
	return (1);
}

static int
lfetch_get_url(lua_State *L)
{
	const char *url = luaL_checkstring(L, 1);
	const char *out = luaL_checkstring(L, 2);
	struct url *u;
	FILE *fetch;
	FILE *file;
	char *headers = NULL;

	/* Get optional headers table */
	if (lua_gettop(L) >= 3) {
		headers = build_headers(L, 3);
		if (headers == NULL) {
			lua_pushnil(L);
			lua_pushstring(L, "Failed to allocate memory for headers");
			return 2;
		}
	} else {
		headers = strdup("");
	}

	u = fetchParseURL(url);
	if (u == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to parse URL");
		return (2);
	}

	file = fopen(out, "w");
	if (file == NULL) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to open output file: %s", strerror(errno));
		return 2;
	}

	fetch = fetchGet(u, headers);
	free(headers);
	if (fetch == NULL) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to read from URL: %s", strerror(errno));
		return 2;
	}

	char buf[CHUNK_SIZE];
	size_t bytes;

	while ((bytes = fread(buf, 1, CHUNK_SIZE, fetch)) > 0) {
		if (fwrite(buf, 1, bytes, file) != bytes) {
			fclose(fetch);
			fclose(file);
			fetchFreeURL(u);
			lua_pushnil(L);
			lua_pushfstring(L, "Failed to write to file: %s", strerror(errno));
			return 2;
		}
	}

	fclose(fetch);
	fclose(file);
	fetchFreeURL(u);
	lua_pushboolean(L, 1);
	return 1;
}

static int
lfetch_put_url(lua_State *L)
{
	const char *url = luaL_checkstring(L, 1);
	const char *in = luaL_checkstring(L, 2);
	struct url *u;
	FILE *fetch;
	FILE *file;
	char *headers = NULL;
	char *buf;
	struct stat sb;
	size_t size;

	u = fetchParseURL(url);
	if (u == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to parse URL");
		return (2);
	}

	file = fopen(in, "r");
	if (file == NULL) {
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to open input file: %s", strerror(errno));
		return 2;
	}

	if (fstat(fileno(file), &sb) == -1) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to stat input file: %s", strerror(errno));
		return 2;
	}

	size = sb.st_size;
	buf = malloc(size);
	if (buf == NULL) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushstring(L, "Failed to allocate memory for request");
		return 2;
	}

	if (fread(buf, 1, size, file) != size) {
		free(buf);
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushstring(L, "Failed to read input file");
		return 2;
	}
	fclose(file);

	/* Get optional headers table */
	if (lua_gettop(L) >= 3) {
		headers = build_headers(L, 3);
		if (headers == NULL) {
			free(buf);
			lua_pushnil(L);
			lua_pushstring(L, "Failed to allocate memory for headers");
			return 2;
		}
	} else {
		headers = strdup("");
	}

	fetch = fetchReqHTTP(u, "PUT", buf, headers, "");
	free(headers);
	free(buf);
	if (fetch == NULL) {
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to PUT to URL: %s", strerror(errno));
		return 2;
	}

	fclose(fetch);
	fetchFreeURL(u);
	lua_pushboolean(L, 1);
	return 1;
}

static int
lfetch_post_url(lua_State *L)
{
	const char *url = luaL_checkstring(L, 1);
	const char *in = luaL_checkstring(L, 2);
	struct url *u;
	FILE *fetch;
	FILE *file;
	char *buf;
	char *headers = NULL;
	struct stat sb;
	size_t size;

	u = fetchParseURL(url);
	if (u == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to parse URL");
		return (2);
	}

	file = fopen(in, "r");
	if (file == NULL) {
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to open input file: %s", strerror(errno));
		return 2;
	}

	if (fstat(fileno(file), &sb) == -1) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to stat input file: %s", strerror(errno));
		return 2;
	}

	size = sb.st_size;
	buf = malloc(size);
	if (buf == NULL) {
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushstring(L, "Failed to allocate memory for request");
		return 2;
	}

	if (fread(buf, 1, size, file) != size) {
		free(buf);
		fclose(file);
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushstring(L, "Failed to read input file");
		return 2;
	}
	fclose(file);

	/* Get optional headers table */
	if (lua_gettop(L) >= 3) {
		headers = build_headers(L, 3);
		if (headers == NULL) {
			free(buf);
			lua_pushnil(L);
			lua_pushstring(L, "Failed to allocate memory for headers");
			return 2;
		}
	} else {
		headers = strdup("");
	}

	fetch = fetchReqHTTP(u, "POST", buf, headers, "");
	free(headers);
	free(buf);
	if (fetch == NULL) {
		fetchFreeURL(u);
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to POST to URL: %s", strerror(errno));
		return 2;
	}

	fclose(fetch);
	fetchFreeURL(u);
	lua_pushboolean(L, 1);
	return 1;
}

static const struct
luaL_Reg fetchlib[] = {
	{"get_url", lfetch_get_url},
	{"parse_url", lfetch_parse_url},
	{"put_url", lfetch_put_url},
	{"post_url", lfetch_post_url},
	{NULL, NULL}
};

int
luaopen_fetch(lua_State *L)
{
	luaL_newlib(L, fetchlib);
	return (1);
}

