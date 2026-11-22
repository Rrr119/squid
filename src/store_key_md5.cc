/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager MD5 Cache Keys */

#include "squid.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#include "HttpRequest.h"
#include "md5.h"
#include "SquidConfig.h"
#include "store_key_md5.h"

const char *
storeKeyText(const cache_key *key)
{
    if (!key)
        return "[null_store_key]";

    static char buf[SQUID_MD5_DIGEST_LENGTH * 2+1];
    int i;

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i)
        snprintf(&buf[i*2],sizeof(buf) - i*2, "%02X", *(key + i));

    return buf;
}

const cache_key *
storeKeyScan(const char *buf)
{
    static unsigned char digest[SQUID_MD5_DIGEST_LENGTH];
    int i;
    int j = 0;
    char t[3];

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i) {
        t[0] = *(buf + (j++));
        t[1] = *(buf + (j++));
        t[2] = '\0';
        *(digest + i) = (unsigned char) strtol(t, nullptr, 16);
    }

    return digest;
}

int
storeKeyHashCmp(const void *a, const void *b)
{
    const unsigned char *A = (const unsigned char *)a;
    const unsigned char *B = (const unsigned char *)b;
    int i;

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i) {
        if (A[i] < B[i])
            return -1;

        if (A[i] > B[i])
            return 1;
    }

    return 0;
}

unsigned int
storeKeyHashHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const unsigned char *digest = (const unsigned char *)key;
    unsigned int i = digest[0]
                     | digest[1] << 8
                     | digest[2] << 16
                     | digest[3] << 24;
    return (i & (--n));
}

const cache_key *
storeKeyPrivate()
{
    // only the count field is required
    // others just simplify searching for keys in a multi-process cache.log
    static struct {
        uint64_t count;
        pid_t pid;
        int32_t kid;
    } key = { 0, getpid(), KidIdentifier };
    static_assert(sizeof(key) == SQUID_MD5_DIGEST_LENGTH);
    ++key.count;
    return reinterpret_cast<cache_key*>(&key);
}

const cache_key *
storeKeyPublic(const char *url, const HttpRequestMethod& method, const KeyScope keyScope)
{
    static cache_key digest[SQUID_MD5_DIGEST_LENGTH];
    unsigned char m = (unsigned char) method.id();
    SquidMD5_CTX M;
    SquidMD5Init(&M);
    SquidMD5Update(&M, &m, sizeof(m));
    SquidMD5Update(&M, (unsigned char *) url, strlen(url));
    if (keyScope)
        SquidMD5Update(&M, &keyScope, sizeof(keyScope));
    SquidMD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublicByRequest(HttpRequest * request, const KeyScope keyScope)
{
    return storeKeyPublicByRequestMethod(request, request->method, keyScope);
}

const cache_key *
storeKeyPublicByRequestMethod(HttpRequest * request, const HttpRequestMethod& method, const KeyScope keyScope)
{
    static cache_key digest[SQUID_MD5_DIGEST_LENGTH];
    unsigned char m = (unsigned char) method.id();
    const SBuf url = request->storeId(); /* returns the right storeID\URL for the MD5 calc */
    SquidMD5_CTX M;
    SquidMD5Init(&M);
    SquidMD5Update(&M, &m, sizeof(m));
    SquidMD5Update(&M, (unsigned char *) url.rawContent(), url.length());
    if (keyScope)
        SquidMD5Update(&M, &keyScope, sizeof(keyScope));

    if (Config.onoff.user_domain_cache_isolation) {
        SBuf userScope;
#if USE_AUTH
        if (request->auth_user_request) {
            if (request->auth_user_request->user())
                userScope = request->auth_user_request->user()->userKey();
            if (userScope.isEmpty() && request->auth_user_request->username())
                userScope = request->auth_user_request->username();
        }
#endif
        const uint32_t userLen = userScope.length();
        SquidMD5Update(&M, reinterpret_cast<const unsigned char *>(&userLen), sizeof(userLen));
        if (userLen)
            SquidMD5Update(&M, reinterpret_cast<const unsigned char *>(userScope.rawContent()), userLen);
        debugs(20, 3, "updating public key by user: " << (userLen ? userScope : SBuf("[anonymous]")) << " for: " << url);
    }

    if (!request->vary_headers.isEmpty()) {
        SquidMD5Update(&M, request->vary_headers.rawContent(), request->vary_headers.length());
        debugs(20, 3, "updating public key by vary headers: " << request->vary_headers << " for: " << url);
    }

    SquidMD5Final(digest, &M);

    return digest;
}

cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = (cache_key *)memAllocate(MEM_MD5_DIGEST);
    memcpy(dup, key, SQUID_MD5_DIGEST_LENGTH);
    return dup;
}

cache_key *
storeKeyCopy(cache_key * dst, const cache_key * src)
{
    memcpy(dst, src, SQUID_MD5_DIGEST_LENGTH);
    return dst;
}

void
storeKeyFree(const cache_key * key)
{
    memFree((void *) key, MEM_MD5_DIGEST);
}

int
storeKeyHashBuckets(int nbuckets)
{
    int n = 0x2000;

    while (n < nbuckets)
        n <<= 1;

    return n;
}

