/*-
 * Copyright (c) 2023, 2024 Dave Cottlehuber <dch@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* #include <sys/cdefs.h> */

#include <errno.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <fetch.h>

#include <lua.h>
#include "lauxlib.h"
#include "lfetch.h"

#define CHUNK_SIZE 4096

/*
 * Minimal implementation of libfetch
 */

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

	fetch = fetchGet(u, "");
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

static const struct
luaL_Reg fetchlib[] = {
	{"get_url", lfetch_get_url},
	{"parse_url", lfetch_parse_url},
	{NULL, NULL}
};

int
luaopen_fetch(lua_State *L)
{
	luaL_newlib(L, fetchlib);
	return (1);
}

