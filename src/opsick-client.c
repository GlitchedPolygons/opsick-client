/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "../include/opsick/opsick-client.h"
#include "jsmn.h"

#include "ed25519.h"
#include "pwcrypt.h"
#include "cecies/util.h"
#include "cecies/keygen.h"
#include "cecies/encrypt.h"
#include "cecies/decrypt.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <glitchedhttps.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/platform_util.h>

#define OPSICK_SERVER_KEY_REFRESH_INTERVAL_S 3600
#define OPSICK_CLIENT_KEY_ARGON2_T 64
#define OPSICK_CLIENT_KEY_ARGON2_M 65536
#define OPSICK_CLIENT_KEY_ARGON2_P 2
#define OPSICK_CLIENT_MAX_URL_LENGTH 1024

const static unsigned char Z256[256] = { 0x00 };

static int initialized = 0;

int opsick_client_init()
{
    if (initialized)
    {
        return OPSICK_CLIENT_SUCCESS;
    }

    if (glitchedhttps_init() != 0)
    {
        return OPSICK_CLIENT_INIT_FAILED;
    }

    initialized = 1;
    return OPSICK_CLIENT_SUCCESS;
}

int opsick_client_free()
{
    if (!initialized)
    {
        return OPSICK_CLIENT_SUCCESS;
    }

    glitchedhttps_free();
    initialized = 0;
    return OPSICK_CLIENT_SUCCESS;
}

static inline int is_valid_server_url(const char* server_url, size_t* out_server_url_length)
{
    return server_url != NULL //
            && (*out_server_url_length = strlen(server_url)) != 0 //
            && (strstr(server_url, "http://") || strstr(server_url, "https://")) //
            && server_url[*out_server_url_length - 1] != '/'; // NO TRAILING SLASHES FOR BASE URLS!
}

static inline int is_successful(struct glitchedhttps_response* response)
{
    return response != NULL //////////////////
            && response->status_code >= 200 //
            && response->status_code < 300; //
}

static inline int has_totp_set(const struct opsick_client_user_context* ctx)
{
    for (size_t i = 0; i < sizeof(ctx->totp); ++i)
    {
        if (ctx->totp[i] != 0x00)
            return 1;
    }
    return 0;
}

static inline int has_private_ed25519_key(const struct opsick_client_user_context* ctx)
{
    for (size_t i = 0; i < sizeof(ctx->user_private_ed25519_key); ++i)
    {
        if (ctx->user_private_ed25519_key[i] != 0x00)
            return 1;
    }
    return 0;
}

static inline int has_private_curve448_key(const struct opsick_client_user_context* ctx)
{
    for (size_t i = 0; i < sizeof(ctx->user_private_curve448_key); ++i)
    {
        if (ctx->user_private_curve448_key[i] != 0x00)
            return 1;
    }
    return 0;
}

static inline int has_private_keys(const struct opsick_client_user_context* ctx)
{
    return has_private_ed25519_key(ctx) && has_private_curve448_key(ctx);
}

static inline size_t opsick_strnlen(const char* str, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (str[i] == '\0')
            return i;
    }
    return len;
}

static inline char* opsick_strndup(const char* str, size_t len)
{
    const size_t act = opsick_strnlen(str, len);
    char* dst = malloc(act + 1);
    if (dst != NULL)
    {
        memmove(dst, str, act);
        dst[act] = '\0';
    }
    return dst;
}

static inline int opsick_strncmpic(const char* str1, const char* str2, size_t n)
{
    size_t cmp = 0;
    int ret = INT_MIN;

    if (str1 == NULL || str2 == NULL)
    {
        return ret;
    }

    while ((*str1 || *str2) && cmp < n)
    {
        if ((ret = tolower((int)(*str1)) - tolower((int)(*str2))) != 0)
        {
            break;
        }
        ++cmp;
        ++str1;
        ++str2;
    }

    return ret;
}

static inline void sign(const struct opsick_client_user_context* ctx, const char* string, const size_t string_length, char out[128 + 1])
{
    unsigned char pub[32 + 1];
    unsigned char prv[32 + 1];
    cecies_hexstr2bin(ctx->user_public_ed25519_key, 64, pub, sizeof(pub), NULL);
    cecies_hexstr2bin(ctx->user_private_ed25519_key, 64, prv, sizeof(prv), NULL);

    uint8_t sig[64];
    ed25519_sign(sig, (unsigned char*)string, string_length ? string_length : strlen(string), pub, prv);

    cecies_bin2hexstr(sig, sizeof(sig), out, 128 + 1, NULL, 0);

    mbedtls_platform_zeroize(prv, sizeof(prv));
    mbedtls_platform_zeroize(pub, sizeof(pub));
    mbedtls_platform_zeroize(sig, sizeof(sig));
}

static int is_valid_server_sig(const struct opsick_client_user_context* ctx, const char* msg, const size_t msg_length, struct glitchedhttps_response* response)
{
    char sig_hex[128 + 1] = { 0x00 };

    for (size_t i = 0; i < response->headers_count; ++i)
    {
        const struct glitchedhttps_header h = response->headers[i];
        if (opsick_strncmpic(h.type, "ed25519-signature", 17) == 0)
        {
            snprintf(sig_hex, sizeof(sig_hex), "%s", h.value);
            break;
        }
    }

    if (memcmp(sig_hex, Z256, sizeof(sig_hex)) == 0)
    {
        return 0;
    }

    unsigned char sig[64 + 1];
    if (cecies_hexstr2bin(sig_hex, 128, sig, sizeof(sig), NULL) != 0)
    {
        return 0;
    }

    unsigned char pubkey[32 + 1];
    if (cecies_hexstr2bin(ctx->server_public_ed25519_key, 64, pubkey, sizeof(pubkey), NULL) != 0)
    {
        return 0;
    }

    return ed25519_verify(sig, (const unsigned char*)msg, msg_length, pubkey);
}

static inline cecies_curve448_key string2curve448key(const char* key_hexstr)
{
    struct cecies_curve448_key out;
    memcpy(out.hexstring, key_hexstr, 112);
    out.hexstring[112] = '\0';
    return out;
}

static inline int refresh_server_keys(struct opsick_client_user_context* ctx, const int force)
{
    if (force || time(0) > ctx->last_server_key_refresh + OPSICK_SERVER_KEY_REFRESH_INTERVAL_S)
    {
        return opsick_client_get_server_public_keys(ctx);
    }
    return OPSICK_CLIENT_KEY_REGEN_NOT_PERFORMED;
}

static inline int jsoneq(const char* json, const jsmntok_t* token, const char* string, const int string_length)
{
    const size_t token_length = token->end - token->start;
    return token->type != JSMN_STRING || string_length != token_length || strncmp(json + token->start, string, token_length) != 0;
}

static inline void sha512(const char* msg, const size_t msg_length, char out_hexstr[128 + 1])
{
    unsigned char hash[64];
    mbedtls_sha512((const unsigned char*)msg, msg_length, hash, 0);
    cecies_bin2hexstr(hash, sizeof(hash), out_hexstr, 128 + 1, NULL, 0);
}

static inline int encrypt_sign_and_post(struct opsick_client_user_context* ctx, const char* request_body, const size_t request_body_length, struct glitchedhttps_response** out_response, char* url, const size_t url_length)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    int r = OPSICK_CLIENT_FAILURE;
    char sig[128 + 1] = { 0x00 };
    uint8_t* encrypted_request_body = NULL;
    size_t encrypted_request_body_length = 0;
    struct glitchedhttps_request request = { 0x00 };

    refresh_server_keys(ctx, 0);

    r = cecies_curve448_encrypt((const uint8_t*)request_body, request_body_length, 0, string2curve448key(ctx->server_public_curve448_key), &encrypted_request_body, &encrypted_request_body_length, 1);
    if (r != 0)
    {
        r = OPSICK_CLIENT_CECIES_ENCRYPTION_FAILED;
        goto exit;
    }

    sign(ctx, request_body, request_body_length, sig);

    request.url = url;
    request.url_length = url_length;
    request.method = GLITCHEDHTTPS_POST;
    request.content = (char*)encrypted_request_body;
    request.content_length = encrypted_request_body_length;
    request.content_type = "text/plain";
    request.content_type_length = 10;

    struct glitchedhttps_header additional_headers[] = {
        { "ed25519-signature", sig },
    };

    request.additional_headers_count = 1;
    request.additional_headers = additional_headers;

    r = glitchedhttps_submit(&request, out_response);

    mbedtls_platform_zeroize(&request, sizeof(request));
    mbedtls_platform_zeroize(additional_headers, sizeof(additional_headers));

exit:
    if (encrypted_request_body)
    {
        mbedtls_platform_zeroize(encrypted_request_body, encrypted_request_body_length);
        free(encrypted_request_body);
    }
    return r;
}

int opsick_client_test_connection(const char* server_url)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    static const char path[] = "/pubkey";
    static const size_t path_length = sizeof(path) - 1;

    size_t server_url_length;
    if (!is_valid_server_url(server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", server_url, path);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
    int r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = OPSICK_CLIENT_CONNECTION_TO_SERVER_FAILED;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_CONNECTION_TO_SERVER_FAILED;
        goto exit;
    }

    if (!strstr(response->content, "\"public_key_ed25519\"") || !strstr(response->content, "\"public_key_curve448\""))
    {
        r = OPSICK_CLIENT_CONNECTION_TO_SERVER_WEIRD;
        goto exit;
    }

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_get_server_public_keys(struct opsick_client_user_context* ctx)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    static const char path[] = "/pubkey";
    static const size_t path_length = sizeof(path) - 1;

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    jsmn_parser parser;
    jsmntok_t tokens[8] = { 0x00 };

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.url_length = server_url_length + path_length;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
    r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = OPSICK_CLIENT_REQUEST_SUBMISSION_TO_SERVER_FAILED;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    jsmn_init(&parser);
    const int64_t n = jsmn_parse(&parser, response->content, (int64_t)response->content_length, tokens, 8);

    if (n < 1 || tokens[0].type != JSMN_OBJECT)
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
        goto exit;
    }

    for (int64_t i = 1; i < n; ++i)
    {
        jsmntok_t* token = &tokens[i];

        if (jsoneq(response->content, token, "public_key_ed25519", 18) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            const int64_t len = t.end - t.start;
            if (len != 64) // Ensure valid Ed25519 key length!
            {
                r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
                goto exit;
            }
            memcpy(ctx->server_public_ed25519_key, response->content + t.start, len);
            ctx->server_public_ed25519_key[64] = '\0';
            continue;
        }

        if (jsoneq(response->content, token, "public_key_curve448", 19) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            const int64_t len = t.end - t.start;
            if (len != 112) // Ensure valid Curve448 key length!
            {
                r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
                goto exit;
            }
            memcpy(ctx->server_public_curve448_key, response->content + t.start, len);
            ctx->server_public_curve448_key[112] = '\0';
            continue;
        }
    }

    ctx->last_server_key_refresh = time(0);

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
    mbedtls_platform_zeroize(&parser, sizeof(parser));
    mbedtls_platform_zeroize(tokens, sizeof(tokens));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_post_passwd(struct opsick_client_user_context* ctx, const char* new_pw)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    static const char path[] = "/users/passwd";
    static const size_t path_length = sizeof(path) - 1;

    size_t new_pw_length;
    size_t server_url_length;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    if (new_pw == NULL || (new_pw_length = strlen(new_pw)) == 0)
    {
        return OPSICK_CLIENT_INVALID_ARGS;
    }

    if (!has_private_keys(ctx))
    {
        return OPSICK_CLIENT_MISSING_PRIVATE_KEYS;
    }

    uint8_t* encrypted_ed25519_private_key = NULL;
    size_t encrypted_ed25519_private_key_length = 0;

    uint8_t* encrypted_curve448_private_key = NULL;
    size_t encrypted_curve448_private_key_length = 0;

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->pw, strlen(ctx->pw), pw_sha512);

    char new_pw_sha512[128 + 1];
    sha512(new_pw, new_pw_length, new_pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    char request_body_json[2048] = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_ed25519_key, 128, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_ed25519_private_key, &encrypted_ed25519_private_key_length, 1);
    if (r != 0)
    {
        r = OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED;
        goto exit;
    }

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_curve448_key, 112, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_curve448_private_key, &encrypted_curve448_private_key_length, 1);
    if (r != 0)
    {
        r = OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED;
        goto exit;
    }

    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"new_pw\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"encrypted_private_key_curve448\":\"%s\",\"totp\":\"%s\"}", ctx->id, pw_sha512, new_pw_sha512, encrypted_ed25519_private_key, encrypted_curve448_private_key, has_totp_set(ctx) ? ctx->totp : "");

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);
    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    mbedtls_platform_zeroize(ctx->pw, sizeof(ctx->pw));
    memcpy(ctx->pw, new_pw, new_pw_length);

    if (!is_valid_server_sig(ctx, new_pw_sha512, 128, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    if (encrypted_ed25519_private_key)
    {
        mbedtls_platform_zeroize(encrypted_ed25519_private_key, encrypted_ed25519_private_key_length);
        free(encrypted_ed25519_private_key);
    }

    if (encrypted_curve448_private_key)
    {
        mbedtls_platform_zeroize(encrypted_curve448_private_key, encrypted_curve448_private_key_length);
        free(encrypted_curve448_private_key);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(new_pw_sha512, sizeof(new_pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_get_user(struct opsick_client_user_context* ctx, const char* body_sha512, char** out_body_json, size_t* out_body_json_length)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    size_t server_url_length;

    static const char path[] = "/users";
    static const size_t path_length = sizeof(path) - 1;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    if (out_body_json == NULL || out_body_json_length == NULL)
    {
        return OPSICK_CLIENT_INVALID_ARGS;
    }

    char pw_sha512[128 + 1] = { 0x00 };
    const size_t pw_length = strlen(ctx->pw);
    sha512(ctx->pw, pw_length, pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    char request_body_json[512] = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    uint8_t* decrypted_response_body_json = NULL;
    size_t decrypted_response_body_json_length = 0;

    jsmn_parser parser;
    jsmntok_t tokens[32] = { 0x00 };
    jsmn_init(&parser);

    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"body_sha512\":\"%s\"}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "", body_sha512 ? body_sha512 : "");

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    if (cecies_curve448_decrypt((const uint8_t*)response->content, response->content_length, 1, string2curve448key(ctx->user_private_curve448_key), &decrypted_response_body_json, &decrypted_response_body_json_length) != 0)
    {
        r = OPSICK_CLIENT_CECIES_DECRYPTION_FAILED;
        goto exit;
    }

    const int64_t n = jsmn_parse(&parser, (const char*)decrypted_response_body_json, decrypted_response_body_json_length, tokens, 32);

    if (n < 1 || tokens[0].type != JSMN_OBJECT)
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
        goto exit;
    }

    for (int64_t i = 1; i < n; ++i)
    {
        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "id", 2) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* nr = opsick_strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            ctx->id = (uint64_t)strtoull(nr, NULL, 10);
            free(nr);
            continue;
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "iat_utc", 7) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* nr = opsick_strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            ctx->iat_utc = (uint64_t)strtoull(nr, NULL, 10);
            free(nr);
            continue;
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "exp_utc", 7) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* nr = opsick_strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            ctx->exp_utc = (uint64_t)strtoull(nr, NULL, 10);
            free(nr);
            continue;
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "lastmod_utc", 11) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* nr = opsick_strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            ctx->lastmod_utc = (uint64_t)strtoull(nr, NULL, 10);
            free(nr);
            continue;
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "body", 4) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            r = pwcrypt_decrypt((const uint8_t*)decrypted_response_body_json + t.start, t.end - t.start, (const uint8_t*)ctx->pw, pw_length, (uint8_t**)out_body_json, out_body_json_length);
            if (r != 0)
            {
                r = OPSICK_CLIENT_PWCRYPT_DECRYPTION_FAILED;
                goto exit;
            }
            continue;
        }
    }

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    if (decrypted_response_body_json)
    {
        mbedtls_platform_zeroize(decrypted_response_body_json, decrypted_response_body_json_length);
        free(decrypted_response_body_json);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(tokens, sizeof(tokens));
    mbedtls_platform_zeroize(&parser, sizeof(parser));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_get_userkeys(struct opsick_client_user_context* ctx)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    size_t server_url_length;

    static const char path[] = "/users/keys";
    static const size_t path_length = sizeof(path) - 1;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    char pw_sha512[128 + 1] = { 0x00 };
    const size_t pw_length = strlen(ctx->pw);
    sha512(ctx->pw, pw_length, pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    char request_body_json[512] = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    jsmn_parser parser;
    jsmntok_t tokens[32] = { 0x00 };
    jsmn_init(&parser);

    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\"}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "");

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    // We'll just assume the response->content_length is < INT64_MAX to avoid yet another if statement: it's very unlikely to have such a huge response anyway..
    const int64_t n = jsmn_parse(&parser, response->content, (int64_t)response->content_length, tokens, 32);

    if (n < 1 || tokens[0].type != JSMN_OBJECT)
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
        goto exit;
    }

    for (int64_t i = 1; i < n; ++i)
    {
        if (jsoneq(response->content, &tokens[i], "public_key_ed25519", 18) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            snprintf(ctx->user_public_ed25519_key, t.end - t.start, "%s", response->content + t.start);
            continue;
        }

        if (jsoneq(response->content, &tokens[i], "encrypted_private_key_ed25519", 29) == 0)
        {
            jsmntok_t t = tokens[i + 1];

            uint8_t* decrypted_key = NULL;
            size_t decrypted_key_length = 0;

            if (pwcrypt_decrypt((const uint8_t*)response->content + t.start, t.end - t.start, (const uint8_t*)ctx->pw, pw_length, &decrypted_key, &decrypted_key_length) != 0)
            {
                r = OPSICK_CLIENT_PWCRYPT_DECRYPTION_FAILED;
                goto exit;
            }

            if (snprintf(ctx->user_private_ed25519_key, sizeof(ctx->user_private_ed25519_key), "%s", decrypted_key) != 128)
            {
                r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
                mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
                free(decrypted_key);
                goto exit;
            }

            mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
            free(decrypted_key);
            continue;
        }

        if (jsoneq(response->content, &tokens[i], "public_key_curve448", 19) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            snprintf(ctx->user_public_curve448_key, t.end - t.start, "%s", response->content + t.start);
            continue;
        }

        if (jsoneq(response->content, &tokens[i], "encrypted_private_key_curve448", 30) == 0)
        {
            jsmntok_t t = tokens[i + 1];

            uint8_t* decrypted_key = NULL;
            size_t decrypted_key_length = 0;

            if (pwcrypt_decrypt((const uint8_t*)response->content + t.start, t.end - t.start, (const uint8_t*)ctx->pw, pw_length, &decrypted_key, &decrypted_key_length) != 0)
            {
                r = OPSICK_CLIENT_PWCRYPT_DECRYPTION_FAILED;
                goto exit;
            }

            if (snprintf(ctx->user_private_curve448_key, sizeof(ctx->user_private_curve448_key), "%s", decrypted_key) != 112)
            {
                r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
                mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
                free(decrypted_key);
                goto exit;
            }

            mbedtls_platform_zeroize(decrypted_key, decrypted_key_length);
            free(decrypted_key);
            continue;
        }
    }

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(tokens, sizeof(tokens));
    mbedtls_platform_zeroize(&parser, sizeof(parser));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_regen_userkeys(struct opsick_client_user_context* ctx, const void* additional_entropy, size_t additional_entropy_length)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    static const char path[] = "/users/keys/update";
    static const size_t path_length = sizeof(path) - 1;

    size_t server_url_length;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    if ((additional_entropy != NULL && additional_entropy_length == 0) || (additional_entropy_length != 0 && additional_entropy == NULL))
    {
        return OPSICK_CLIENT_INVALID_ARGS;
    }

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    cecies_curve448_keypair curve448_keypair;
    cecies_generate_curve448_keypair(&curve448_keypair, additional_entropy, additional_entropy_length);

    unsigned char entropy[256];
    unsigned char ed25519_seed[32];
    unsigned char ed25519_public[32];
    unsigned char ed25519_private[64];
    char ed25519_public_hexstr[64 + 1] = { 0x00 };
    char ed25519_private_hexstr[128 + 1] = { 0x00 };

    cecies_dev_urandom(entropy, sizeof(entropy));

    if (additional_entropy != NULL)
    {
        mbedtls_sha256(additional_entropy, additional_entropy_length, entropy + (sizeof(entropy) - 32), 0);
    }

    char pw_sha512[128 + 1] = { 0x00 };
    const size_t pw_length = strlen(ctx->pw);
    sha512(ctx->pw, pw_length, pw_sha512);

    mbedtls_sha256(entropy, sizeof(entropy), ed25519_seed, 0);
    ed25519_create_keypair(ed25519_public, ed25519_private, ed25519_seed);

    cecies_bin2hexstr(ed25519_public, sizeof(ed25519_public), ed25519_public_hexstr, sizeof(ed25519_public_hexstr), NULL, 0);
    cecies_bin2hexstr(ed25519_private, sizeof(ed25519_private), ed25519_private_hexstr, sizeof(ed25519_private_hexstr), NULL, 0);

    uint8_t* encrypted_ed25519_private_key = NULL;
    size_t encrypted_ed25519_private_key_length = 0;

    uint8_t* encrypted_curve448_private_key = NULL;
    size_t encrypted_curve448_private_key_length = 0;

    struct glitchedhttps_response* response = NULL;

    char request_body_json[1024] = { 0x00 };

    if (pwcrypt_encrypt((const uint8_t*)ed25519_private_hexstr, 128, 8, (const uint8_t*)ctx->pw, pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_ed25519_private_key, &encrypted_ed25519_private_key_length, 1) != 0)
    {
        r = OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED;
        goto exit;
    }

    if (pwcrypt_encrypt((const uint8_t*)curve448_keypair.private_key.hexstring, 112, 8, (const uint8_t*)ctx->pw, pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_curve448_private_key, &encrypted_curve448_private_key_length, 1) != 0)
    {
        r = OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED;
        goto exit;
    }

    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"public_key_ed25519\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"public_key_curve448\":\"%s\",\"encrypted_private_key_curve448\":\"%s\"}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "", ed25519_public_hexstr, encrypted_ed25519_private_key, curve448_keypair.public_key.hexstring, encrypted_curve448_private_key);

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    mbedtls_platform_zeroize(ctx->user_public_ed25519_key, sizeof(ctx->user_public_ed25519_key));
    mbedtls_platform_zeroize(ctx->user_private_ed25519_key, sizeof(ctx->user_private_ed25519_key));
    mbedtls_platform_zeroize(ctx->user_public_curve448_key, sizeof(ctx->user_public_curve448_key));
    mbedtls_platform_zeroize(ctx->user_private_curve448_key, sizeof(ctx->user_private_curve448_key));

    memcpy(ctx->user_public_ed25519_key, ed25519_public_hexstr, 64);
    memcpy(ctx->user_private_ed25519_key, ed25519_private_hexstr, 128);
    memcpy(ctx->user_public_curve448_key, curve448_keypair.public_key.hexstring, 112);
    memcpy(ctx->user_private_curve448_key, curve448_keypair.private_key.hexstring, 112);

    if (!is_valid_server_sig(ctx, pw_sha512, 128, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    if (encrypted_ed25519_private_key)
    {
        mbedtls_platform_zeroize(encrypted_ed25519_private_key, encrypted_ed25519_private_key_length);
        free(encrypted_ed25519_private_key);
    }

    if (encrypted_curve448_private_key)
    {
        mbedtls_platform_zeroize(encrypted_curve448_private_key, encrypted_curve448_private_key_length);
        free(encrypted_curve448_private_key);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    mbedtls_platform_zeroize(ed25519_seed, sizeof(ed25519_seed));
    mbedtls_platform_zeroize(ed25519_public, sizeof(ed25519_public));
    mbedtls_platform_zeroize(ed25519_public_hexstr, sizeof(ed25519_public_hexstr));
    mbedtls_platform_zeroize(ed25519_private, sizeof(ed25519_private));
    mbedtls_platform_zeroize(ed25519_private_hexstr, sizeof(ed25519_private_hexstr));
    mbedtls_platform_zeroize(&curve448_keypair, sizeof(curve448_keypair));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_post_userdel(struct opsick_client_user_context* ctx)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    size_t server_url_length;

    static const char path[] = "/users/delete";
    static const size_t path_length = sizeof(path) - 1;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->pw, strlen(ctx->pw), pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    struct glitchedhttps_response* response = NULL;

    char request_body_json[1024] = { 0x00 };

    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\"}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "");

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    r = 0;

exit:
    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_post_user2fa(struct opsick_client_user_context* ctx, int action, char out_json[256])
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    size_t server_url_length;

    static const char path[] = "/users/2fa";
    static const size_t path_length = sizeof(path) - 1;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    if ((action == 1 && out_json == NULL))
    {
        return OPSICK_CLIENT_INVALID_ARGS;
    }

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->pw, strlen(ctx->pw), pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    uint8_t* decrypted_response_body_json = NULL;
    size_t decrypted_response_body_json_length = 0;

    struct glitchedhttps_response* response = NULL;

    char request_body_json[1024] = { 0x00 };
    const int request_body_json_length = snprintf(request_body_json, sizeof(request_body_json), "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"action\":%d}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "", action);

    r = encrypt_sign_and_post(ctx, request_body_json, request_body_json_length, &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    if (action == 1)
    {
        if (cecies_curve448_decrypt((const uint8_t*)response->content, response->content_length, 1, string2curve448key(ctx->user_private_curve448_key), &decrypted_response_body_json, &decrypted_response_body_json_length) != 0)
        {
            r = OPSICK_CLIENT_CECIES_DECRYPTION_FAILED;
            goto exit;
        }

        if (decrypted_response_body_json_length > 256)
        {
            r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT;
            goto exit;
        }

        snprintf(out_json, 256, "%s", decrypted_response_body_json);
    }

    if (!is_valid_server_sig(ctx, action == 1 ? response->content : pw_sha512, action == 1 ? response->content_length : 128, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    if (decrypted_response_body_json)
    {
        mbedtls_platform_zeroize(decrypted_response_body_json, decrypted_response_body_json_length);
        free(decrypted_response_body_json);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_post_userbody(struct opsick_client_user_context* ctx, const char* body_json)
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    size_t body_json_length;
    size_t server_url_length;

    static const char path[] = "/users/body";
    static const size_t path_length = sizeof(path) - 1;

    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    if (body_json == NULL || (body_json_length = strlen(body_json)) == 0)
    {
        return OPSICK_CLIENT_INVALID_ARGS;
    }

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->pw, strlen(ctx->pw), pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    struct glitchedhttps_response* response = NULL;

    uint8_t* encrypted_body_json = NULL;
    size_t encrypted_body_json_length = 0;

    char* request_body_json = NULL;
    size_t request_body_json_length = 0;

    r = pwcrypt_encrypt((const uint8_t*)body_json, body_json_length, 8, (const uint8_t*)ctx->pw, strlen(ctx->pw), OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_body_json, &encrypted_body_json_length, 1);
    if (r != 0)
    {
        r = OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED;
        goto exit;
    }

    request_body_json_length = 1024 + encrypted_body_json_length;
    request_body_json = malloc(request_body_json_length);

    if (request_body_json == NULL)
    {
        r = OPSICK_CLIENT_OUT_OF_MEMORY;
        goto exit;
    }

    snprintf(request_body_json, request_body_json_length, "{\"id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"body\":\"%s\"}", ctx->id, pw_sha512, has_totp_set(ctx) ? ctx->totp : "", encrypted_body_json);

    r = encrypt_sign_and_post(ctx, request_body_json, strlen(request_body_json), &response, url, server_url_length + path_length);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    if (!is_valid_server_sig(ctx, pw_sha512, 128, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    if (encrypted_body_json)
    {
        mbedtls_platform_zeroize(encrypted_body_json, encrypted_body_json_length);
        free(encrypted_body_json);
    }

    if (request_body_json)
    {
        mbedtls_platform_zeroize(request_body_json, request_body_json_length);
        free(request_body_json);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_get_server_version(struct opsick_client_user_context* ctx, char out_json[128])
{
    if (!initialized)
    {
        return OPSICK_CLIENT_UNINITIALIZED;
    }

    assert(ctx != NULL);

    int r = OPSICK_CLIENT_FAILURE;

    static const char path[] = "/version";
    static const size_t path_length = sizeof(path) - 1;

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return OPSICK_CLIENT_INVALID_SERVER_URL;
    }

    if (server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return OPSICK_CLIENT_SERVER_URL_TOO_LONG;
    }

    refresh_server_keys(ctx, 0);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    request.url = url;
    request.url_length = server_url_length + path_length;
    request.method = GLITCHEDHTTPS_GET;

    r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        goto exit; // Here, the raw GlitchedHTTPS error code is returned.
    }

    if (!is_successful(response))
    {
        r = response ? response->status_code : OPSICK_CLIENT_FAILURE;
        goto exit;
    }

    snprintf(out_json, 128, "%s", response->content);

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE;
        goto exit;
    }

    r = 0;

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
    mbedtls_platform_zeroize(ctx->totp, sizeof(ctx->totp));
    glitchedhttps_response_free(response);

    return r;
}

int opsick_client_get_client_version(char out_version_string[16])
{
    if (out_version_string != NULL)
    {
        snprintf(out_version_string, 16, "%d.%d.%d", OPSICK_CLIENT_VERSION_MAJOR, OPSICK_CLIENT_VERSION_MINOR, OPSICK_CLIENT_VERSION_PATCH);
    }
    return OPSICK_CLIENT_VERSION_MAJOR;
}

#undef OPSICK_SERVER_KEY_REFRESH_INTERVAL_S
#undef OPSICK_CLIENT_KEY_ARGON2_T
#undef OPSICK_CLIENT_KEY_ARGON2_M
#undef OPSICK_CLIENT_KEY_ARGON2_P