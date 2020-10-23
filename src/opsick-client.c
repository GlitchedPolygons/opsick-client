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
#include "../lib/pwcrypt/include/pwcrypt.h"
#include "../lib/cecies/include/cecies/util.h"
#include "../lib/cecies/include/cecies/encrypt.h"
#include "../lib/cecies/include/cecies/decrypt.h"
#include "../lib/ed25519/src/ed25519.h"
#include "../lib/jsmn/jsmn.h"

#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <glitchedhttps.h>
#include <mbedtls/sha512.h>
#include <mbedtls/platform_util.h>

#define OPSICK_SERVER_KEY_REFRESH_INTERVAL_S 3600
#define OPSICK_CLIENT_KEY_ARGON2_T 16
#define OPSICK_CLIENT_KEY_ARGON2_M 65536
#define OPSICK_CLIENT_KEY_ARGON2_P 2

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
    for (int i = 0; i < sizeof(ctx->user_totp); ++i)
    {
        if (ctx->user_totp[i] != 0x00)
            return 1;
    }
    return 0;
}

static inline int has_private_ed25519_key(const struct opsick_client_user_context* ctx)
{
    for (int i = 0; i < sizeof(ctx->user_private_ed25519_key); ++i)
    {
        if (ctx->user_private_ed25519_key[i] != 0x00)
            return 1;
    }
    return 0;
}

static inline int has_private_curve448_key(const struct opsick_client_user_context* ctx)
{
    for (int i = 0; i < sizeof(ctx->user_private_curve448_key); ++i)
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
    return -1;
}

static inline int jsoneq(const char* json, const jsmntok_t* tok, const char* s, const int slen)
{
    return tok->type != JSMN_STRING || slen != tok->end - tok->start || strncmp(json + tok->start, s, tok->end - tok->start) != 0;
}

static inline void sha512(const char* pw, const size_t pwlen, char out[128 + 1])
{
    unsigned char hash[64];
    mbedtls_sha512_ret((const unsigned char*)pw, pwlen, hash, 0);
    cecies_bin2hexstr(hash, sizeof(hash), out, 128 + 1, NULL, 0);
}

int opsick_client_test_connection(const char* server_url)
{
    size_t server_url_length;
    if (!is_valid_server_url(server_url, &server_url_length))
    {
        return -1;
    }

    char url[2048] = { 0x00 };
    snprintf(url, sizeof(url), "%s/pubkey", server_url);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
    int r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = -2;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response->status_code;
        goto exit;
    }

    if (!strstr(response->content, "\"public_key_ed25519\"") || !strstr(response->content, "\"public_key_curve448\""))
    {
        r = -3;
        goto exit;
    }

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
    glitchedhttps_response_free(response);
    return r;
}

int opsick_client_get_server_public_keys(struct opsick_client_user_context* ctx)
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return -1;
    }

    jsmn_parser parser;
    jsmntok_t tokens[8] = { 0x00 };

    char url[2048] = { 0x00 };
    snprintf(url, sizeof(url), "%s/pubkey", ctx->server_url);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.url_length = server_url_length + 7;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
    int r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = -2;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response->status_code;
        goto exit;
    }

    jsmn_init(&parser);
    r = jsmn_parse(&parser, response->content, response->content_length, tokens, 8);

    if (r < 1 || tokens[0].type != JSMN_OBJECT)
    {
        r = -3;
        goto exit;
    }

    for (int i = 1; i < r; ++i)
    {
        if (jsoneq(response->content, &tokens[i], "public_key_ed25519", 18) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            const int len = t.end - t.start;
            if (len != 64) // Ensure valid Ed25519 key length!
            {
                r = -3;
                goto exit;
            }
            memcpy(ctx->server_public_ed25519_key, response->content + t.start, len);
            ctx->server_public_ed25519_key[64] = '\0';
            continue;
        }

        if (jsoneq(response->content, &tokens[i], "public_key_curve448", 19))
        {
            jsmntok_t t = tokens[i + 1];
            const int len = t.end - t.start;
            if (len != 112) // Ensure valid Curve448 key length!
            {
                r = -3;
                goto exit;
            }
            memcpy(ctx->server_public_curve448_key, response->content + t.start, len);
            ctx->server_public_curve448_key[112] = '\0';
            continue;
        }
    }

    ctx->last_server_key_refresh = time(0);
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
    assert(ctx != NULL);

    int r = -1;
    size_t new_pw_length;
    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || !ctx->last_server_key_refresh || new_pw == NULL || (new_pw_length = strlen(new_pw)) == 0 || !has_private_keys(ctx))
    {
        return r;
    }

    refresh_server_keys(ctx, 0);

    uint8_t* enc_ed25519 = NULL;
    size_t enc_ed25519_len = 0;

    uint8_t* enc_curve448 = NULL;
    size_t enc_curve448_len = 0;

    char pw_sha512[128 + 1];
    sha512(ctx->user_pw, strlen(ctx->user_pw), pw_sha512);

    char new_pw_sha512[128 + 1];
    sha512(new_pw, new_pw_length, new_pw_sha512);

    char url[2048] = { 0x00 };
    char json[2048] = { 0x00 };
    char sig[128 + 1] = { 0x00 };
    unsigned char enc_json[4096] = { 0x00 };

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_ed25519_key, 128, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &enc_ed25519, &enc_ed25519_len, 1);
    if (r != 0)
    {
        r = -1;
        goto exit;
    }

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_curve448_key, 112, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &enc_curve448, &enc_curve448_len, 1);
    if (r != 0)
    {
        r = -1;
        goto exit;
    }

    snprintf(url, sizeof(url), "%s/users/passwd", ctx->server_url);
    snprintf(json, sizeof(json), "{\"user_id\":%zu,\"pw\":\"%s\",\"new_pw\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"encrypted_private_key_curve448\":\"%s\",\"totp\":\"%s\"}", ctx->user_id, pw_sha512, new_pw_sha512, enc_ed25519, enc_curve448, has_totp_set(ctx) ? ctx->user_totp : "");

    size_t enc_json_len = 0;

    r = cecies_curve448_encrypt((const unsigned char*)json, strlen(json), string2curve448key(ctx->server_public_curve448_key), enc_json, sizeof(enc_json), &enc_json_len, 1);
    if (r != 0)
    {
        r = -1;
        goto exit;
    }

    sign(ctx, (const char*)enc_json, enc_json_len, sig);

    request.url = url;
    request.url_length = server_url_length + 13;
    request.method = GLITCHEDHTTPS_POST;

    struct glitchedhttps_header additional_headers[] = {
        { "ed25519-signature", sig },
    };

    request.additional_headers = additional_headers;
    request.additional_headers_count = 1;

    r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = -2;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response->status_code;
        goto exit;
    }

    mbedtls_platform_zeroize(ctx->user_pw, sizeof(ctx->user_pw));
    memcpy(ctx->user_pw, new_pw, new_pw_length);

    r = 0;
exit:
    if (enc_ed25519)
    {
        mbedtls_platform_zeroize(enc_ed25519, enc_ed25519_len);
        free(enc_ed25519);
    }
    if (enc_curve448)
    {
        mbedtls_platform_zeroize(enc_curve448, enc_curve448_len);
        free(enc_curve448);
    }

    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(json, sizeof(json));
    mbedtls_platform_zeroize(enc_json, sizeof(enc_json));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(new_pw_sha512, sizeof(new_pw_sha512));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
    mbedtls_platform_zeroize(&request, sizeof(request));
    glitchedhttps_response_free(response);
    return r;
}

int opsick_client_get_user(struct opsick_client_user_context* ctx, const char* body_sha512, char** out_body_json)
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || out_body_json == NULL)
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_get_userkeys(struct opsick_client_user_context* ctx)
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_regen_userkeys(struct opsick_client_user_context* ctx, const void* additional_entropy, size_t additional_entropy_length)
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || (additional_entropy != NULL && additional_entropy_length == 0) || (additional_entropy_length != 0 && additional_entropy == NULL))
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_post_userdel(struct opsick_client_user_context* ctx)
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_post_user2fa(struct opsick_client_user_context* ctx, int action, char out_json[256])
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || (action == 1 && out_json == NULL))
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_post_userbody(struct opsick_client_user_context* ctx, const char* body_json)
{
    assert(ctx != NULL);

    size_t server_url_length;
    size_t body_json_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || body_json == NULL || (body_json_length = strlen(body_json)) == 0)
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_get_server_version(struct opsick_client_user_context* ctx, char out_json[128])
{
    assert(ctx != NULL);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length))
    {
        return -1;
    }

    refresh_server_keys(ctx, 0);

    char url[2048] = { 0x00 };
    snprintf(url, sizeof(url), "%s/version", ctx->server_url);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.url_length = server_url_length + 8;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
    int r = glitchedhttps_submit(&request, &response);

    if (r != GLITCHEDHTTPS_SUCCESS)
    {
        r = -2;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response->status_code;
        goto exit;
    }

    snprintf(out_json, 128, "%s", response->content);
    r = 0;

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
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