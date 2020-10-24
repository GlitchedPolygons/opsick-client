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
#include "../lib/cecies/include/cecies/keygen.h"
#include "../lib/cecies/include/cecies/encrypt.h"
#include "../lib/cecies/include/cecies/decrypt.h"
#include "../lib/ed25519/src/ed25519.h"
#include "../lib/jsmn/jsmn.h"

#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <glitchedhttps.h>
#include <glitchedhttps_strutil.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/platform_util.h>

#define OPSICK_SERVER_KEY_REFRESH_INTERVAL_S 3600
#define OPSICK_CLIENT_KEY_ARGON2_T 64
#define OPSICK_CLIENT_KEY_ARGON2_M 65536
#define OPSICK_CLIENT_KEY_ARGON2_P 2
#define OPSICK_CLIENT_MAX_URL_LENGTH 1024

const static unsigned char Z256[256] = { 0x00 };

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

static int is_valid_server_sig(const struct opsick_client_user_context* ctx, const char* msg, const size_t msg_length, struct glitchedhttps_response* response)
{
    char sig_hex[128 + 1] = { 0x00 };

    for (size_t i = 0; i < response->headers_count; ++i)
    {
        struct glitchedhttps_header h = response->headers[i];
        if (glitchedhttps_strncmpic(h.type, "ed25519-signature", 17) == 0)
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
    return -1;
}

static inline int jsoneq(const char* json, const jsmntok_t* token, const char* string, const int string_length)
{
    return token->type != JSMN_STRING || string_length != token->end - token->start || strncmp(json + token->start, string, token->end - token->start) != 0;
}

static inline void sha512(const char* msg, const size_t msg_length, char out[128 + 1])
{
    unsigned char hash[64];
    mbedtls_sha512_ret((const unsigned char*)msg, msg_length, hash, 0);
    cecies_bin2hexstr(hash, sizeof(hash), out, 128 + 1, NULL, 0);
}

int opsick_client_test_connection(const char* server_url)
{
    int r = -1;

    const char* path = "/pubkey";
    const size_t path_length = strlen(path);

    size_t server_url_length;
    if (!is_valid_server_url(server_url, &server_url_length) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", server_url, path);

    struct glitchedhttps_request request = { 0x00 };
    request.url = url;
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;
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

    int r = -1;

    const char* path = "/pubkey";
    const size_t path_length = strlen(path);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
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

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = -10;
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
    assert(ctx != NULL);

    int r = -1;

    const char* path = "/users/passwd";
    const size_t path_length = strlen(path);

    size_t new_pw_length;
    size_t server_url_length;

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || new_pw == NULL || (new_pw_length = strlen(new_pw)) == 0 || !has_private_keys(ctx) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);

    uint8_t* encrypted_ed25519_private_key = NULL;
    size_t encrypted_ed25519_private_key_length = 0;

    uint8_t* encrypted_curve448_private_key = NULL;
    size_t encrypted_curve448_private_key_length = 0;

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->user_pw, strlen(ctx->user_pw), pw_sha512);

    char new_pw_sha512[128 + 1];
    sha512(new_pw, new_pw_length, new_pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    char request_body_json[2048] = { 0x00 };
    char sig[128 + 1] = { 0x00 };

    unsigned char encrypted_request_body_json[4096] = { 0x00 };

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_ed25519_key, 128, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_ed25519_private_key, &encrypted_ed25519_private_key_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    r = pwcrypt_encrypt((const uint8_t*)ctx->user_private_curve448_key, 112, 8, (const uint8_t*)new_pw, new_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_curve448_private_key, &encrypted_curve448_private_key_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);
    snprintf(request_body_json, sizeof(request_body_json), "{\"user_id\":%zu,\"pw\":\"%s\",\"new_pw\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"encrypted_private_key_curve448\":\"%s\",\"totp\":\"%s\"}", ctx->user_id, pw_sha512, new_pw_sha512, encrypted_ed25519_private_key, encrypted_curve448_private_key, has_totp_set(ctx) ? ctx->user_totp : "");

    size_t encrypted_request_body_json_length = 0;

    r = cecies_curve448_encrypt((const unsigned char*)request_body_json, strlen(request_body_json), string2curve448key(ctx->server_public_curve448_key), encrypted_request_body_json, sizeof(encrypted_request_body_json), &encrypted_request_body_json_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    sign(ctx, (const char*)encrypted_request_body_json, encrypted_request_body_json_length, sig);

    request.url = url;
    request.url_length = server_url_length + path_length;
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

    if (!is_valid_server_sig(ctx, new_pw_sha512, 128, response))
    {
        r = -10;
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
    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(new_pw_sha512, sizeof(new_pw_sha512));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
    mbedtls_platform_zeroize(&request, sizeof(request));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    mbedtls_platform_zeroize(encrypted_request_body_json, sizeof(encrypted_request_body_json));
    glitchedhttps_response_free(response);
    return r;
}

int opsick_client_get_user(struct opsick_client_user_context* ctx, const char* body_sha512, char** out_body_json)
{
    assert(ctx != NULL);

    int r = -1;

    size_t server_url_length;

    const char* path = "/users";
    const size_t path_length = strlen(path);

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || out_body_json == NULL || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->user_pw, strlen(ctx->user_pw), pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    char sig[128 + 1] = { 0x00 };

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    size_t request_body_json_length = 0;
    char request_body_json[512] = { 0x00 };

    size_t encrypted_request_body_json_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(sizeof(request_body_json)));
    unsigned char* encrypted_request_body_json = malloc(encrypted_request_body_json_length);

    size_t decrypted_response_body_json_length = 0;
    unsigned char* decrypted_response_body_json = NULL;

    if (encrypted_request_body_json == NULL)
    {
        r = 20;
        goto exit;
    }

    snprintf(request_body_json, sizeof(request_body_json), "{\"user_id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"body_sha512\":\"%s\"}", ctx->user_id, pw_sha512, has_totp_set(ctx) ? ctx->user_totp : "", body_sha512 ? body_sha512 : "");

    r = cecies_curve448_encrypt((const unsigned char*)request_body_json, request_body_json_length, string2curve448key(ctx->server_public_curve448_key), encrypted_request_body_json, encrypted_request_body_json_length, &encrypted_request_body_json_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    sign(ctx, (const char*)encrypted_request_body_json, encrypted_request_body_json_length, sig);

    request.url = url;
    request.url_length = server_url_length + path_length;
    request.method = GLITCHEDHTTPS_POST;
    request.content = (char*)encrypted_request_body_json;
    request.content_length = encrypted_request_body_json_length;
    request.content_type = "text/plain";
    request.content_type_length = 10;

    struct glitchedhttps_header additional_headers[] = {
        { "ed25519-signature", sig },
    };

    request.additional_headers_count = 1;
    request.additional_headers = additional_headers;

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

    decrypted_response_body_json = malloc((decrypted_response_body_json_length = encrypted_request_body_json_length));
    if (decrypted_response_body_json == NULL)
    {
        r = 20;
        goto exit;
    }

    if (cecies_curve448_decrypt((const unsigned char*)response->content, response->content_length, 1, string2curve448key(ctx->user_private_curve448_key), decrypted_response_body_json, decrypted_response_body_json_length, &decrypted_response_body_json_length) != 0)
    {
        r = 2;
        goto exit;
    }

    jsmn_parser parser;
    jsmntok_t tokens[32] = { 0x00 };

    jsmn_init(&parser);
    r = jsmn_parse(&parser, (const char*)decrypted_response_body_json, decrypted_response_body_json_length, tokens, 8);

    if (r < 1 || tokens[0].type != JSMN_OBJECT)
    {
        r = -3;
        goto exit;
    }

    // TODO: parse json here
    for (int i = 1; i < r; ++i)
    {
        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "id", 2) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* id = strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            ctx->user_id = (uint64_t)strtoull(id, NULL, 10);
            free(id);
            continue;
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "iat_utc", 7) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* iat_utc = strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            // TODO write where here?
            free(iat_utc);
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "exp_utc", 7) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* exp_utc = strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            // TODO write strtoull where here?
            free(exp_utc);
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "lastmod_utc", 11) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            char* lastmod_utc = strndup((const char*)decrypted_response_body_json + t.start, t.end - t.start);
            // TODO write strtoull where here?
            free(lastmod_utc);
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "body", 4) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            // TODO: write body here
        }

        if (jsoneq((const char*)decrypted_response_body_json, &tokens[i], "body_sha512", 11) == 0)
        {
            jsmntok_t t = tokens[i + 1];
            // TODO write body sha512 here and compare
        }
    }

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = -10;
        goto exit;
    }

    r = 0;
exit:
    if (encrypted_request_body_json)
    {
        mbedtls_platform_zeroize(encrypted_request_body_json, encrypted_request_body_json_length);
        free(encrypted_request_body_json);
    }
    if (decrypted_response_body_json)
    {
        mbedtls_platform_zeroize(decrypted_response_body_json, decrypted_response_body_json_length);
        free(decrypted_response_body_json);
    }
    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
    mbedtls_platform_zeroize(&request, sizeof(request));
    glitchedhttps_response_free(response);
    return r;
}

int opsick_client_get_userkeys(struct opsick_client_user_context* ctx)
{
    assert(ctx != NULL);

    int r = -1;

    size_t server_url_length;

    const char* path = "/users/keys";
    const size_t path_length = strlen(path);

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    // TODO: impl!
    refresh_server_keys(ctx, 0);
}

int opsick_client_regen_userkeys(struct opsick_client_user_context* ctx, const void* additional_entropy, size_t additional_entropy_length)
{
    assert(ctx != NULL);

    int r = -1;

    const char* path = "/users/keys/update";
    const size_t path_length = strlen(path);

    size_t server_url_length;

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || (additional_entropy != NULL && additional_entropy_length == 0) || (additional_entropy_length != 0 && additional_entropy == NULL) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    cecies_curve448_keypair curve448_keypair;
    cecies_generate_curve448_keypair(&curve448_keypair, additional_entropy, additional_entropy_length);

    char sig[128 + 1] = { 0x00 };

    unsigned char entropy[256];
    unsigned char ed25519_seed[32];
    unsigned char ed25519_public[32];
    unsigned char ed25519_private[64];
    char ed25519_public_hexstr[64 + 1] = { 0x00 };
    char ed25519_private_hexstr[128 + 1] = { 0x00 };

    cecies_dev_urandom(entropy, sizeof(entropy));

    if (additional_entropy != NULL)
    {
        mbedtls_sha256_ret(additional_entropy, additional_entropy_length, entropy + (sizeof(entropy) - 32), 0);
    }

    char pw_sha512[128 + 1] = { 0x00 };
    const size_t user_pw_length = strlen(ctx->user_pw);
    sha512(ctx->user_pw, user_pw_length, pw_sha512);

    mbedtls_sha256_ret(entropy, sizeof(entropy), ed25519_seed, 0);
    ed25519_create_keypair(ed25519_public, ed25519_private, ed25519_seed);

    cecies_bin2hexstr(ed25519_public, sizeof(ed25519_public), ed25519_public_hexstr, sizeof(ed25519_public_hexstr), NULL, 0);
    cecies_bin2hexstr(ed25519_private, sizeof(ed25519_private), ed25519_private_hexstr, sizeof(ed25519_private_hexstr), NULL, 0);

    uint8_t* encrypted_ed25519_private_key = NULL;
    size_t encrypted_ed25519_private_key_length = 0;

    uint8_t* encrypted_curve448_private_key = NULL;
    size_t encrypted_curve448_private_key_length = 0;

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    char request_body_json[1024] = { 0x00 };

    unsigned char encrypted_request_body_json[2048] = { 0x00 };
    size_t encrypted_request_body_json_length = 0;

    if (pwcrypt_encrypt((const uint8_t*)ed25519_private_hexstr, 128, 8, (const uint8_t*)ctx->user_pw, user_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_ed25519_private_key, &encrypted_ed25519_private_key_length, 1) != 0)
    {
        r = 1;
        goto exit;
    }

    if (pwcrypt_encrypt((const uint8_t*)curve448_keypair.private_key.hexstring, 112, 8, (const uint8_t*)ctx->user_pw, user_pw_length, OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_curve448_private_key, &encrypted_curve448_private_key_length, 1) != 0)
    {
        r = 1;
        goto exit;
    }

    snprintf(request_body_json, sizeof(request_body_json), "{\"user_id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"public_key_ed25519\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"public_key_curve448\":\"%s\",\"encrypted_private_key_curve448\":\"%s\"}", ctx->user_id, pw_sha512, has_totp_set(ctx) ? ctx->user_totp : "", ed25519_public_hexstr, encrypted_ed25519_private_key, curve448_keypair.public_key.hexstring, encrypted_curve448_private_key);

    r = cecies_curve448_encrypt((const unsigned char*)request_body_json, strlen(request_body_json), string2curve448key(ctx->server_public_curve448_key), encrypted_request_body_json, sizeof(encrypted_request_body_json), &encrypted_request_body_json_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    sign(ctx, (const char*)encrypted_request_body_json, encrypted_request_body_json_length, sig);

    request.url = url;
    request.url_length = server_url_length + path_length;
    request.method = GLITCHEDHTTPS_POST;
    request.content = (char*)encrypted_request_body_json;
    request.content_length = encrypted_request_body_json_length;
    request.content_type = "text/plain";
    request.content_type_length = 10;

    struct glitchedhttps_header additional_headers[] = {
        { "ed25519-signature", sig },
    };

    request.additional_headers_count = 1;
    request.additional_headers = additional_headers;

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
        r = -10;
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
    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
    mbedtls_platform_zeroize(&request, sizeof(request));
    mbedtls_platform_zeroize(request_body_json, sizeof(request_body_json));
    mbedtls_platform_zeroize(encrypted_request_body_json, sizeof(encrypted_request_body_json));
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
    assert(ctx != NULL);

    int r = -1;

    size_t server_url_length;

    const char* path = "/users/delete";
    const size_t path_length = strlen(path);

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_post_user2fa(struct opsick_client_user_context* ctx, int action, char out_json[256])
{
    assert(ctx != NULL);

    int r = -1;

    size_t server_url_length;

    const char* path = "/users/2fa";
    const size_t path_length = strlen(path);

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || (action == 1 && out_json == NULL) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);
}

int opsick_client_post_userbody(struct opsick_client_user_context* ctx, const char* body_json)
{
    assert(ctx != NULL);

    int r = -1;

    size_t body_json_length;
    size_t server_url_length;

    const char* path = "/users/body";
    const size_t path_length = strlen(path);

    if (!is_valid_server_url(ctx->server_url, &server_url_length) || body_json == NULL || (body_json_length = strlen(body_json)) == 0 || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
    }

    refresh_server_keys(ctx, 0);

    char pw_sha512[128 + 1] = { 0x00 };
    sha512(ctx->user_pw, strlen(ctx->user_pw), pw_sha512);

    char url[OPSICK_CLIENT_MAX_URL_LENGTH] = { 0x00 };
    snprintf(url, sizeof(url), "%s%s", ctx->server_url, path);

    char sig[128 + 1] = { 0x00 };

    struct glitchedhttps_request request = { 0x00 };
    struct glitchedhttps_response* response = NULL;

    uint8_t* encrypted_body_json = NULL;
    size_t encrypted_body_json_length = 0;

    char* request_body_json = NULL;
    size_t request_body_json_length = 0;

    unsigned char* encrypted_request_body_json = NULL;
    size_t encrypted_request_body_json_length = 0;

    r = pwcrypt_encrypt((const uint8_t*)body_json, body_json_length, 8, (const uint8_t*)ctx->user_pw, strlen(ctx->user_pw), OPSICK_CLIENT_KEY_ARGON2_T, OPSICK_CLIENT_KEY_ARGON2_M, OPSICK_CLIENT_KEY_ARGON2_P, 1, &encrypted_body_json, &encrypted_body_json_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    request_body_json_length = 1024 + encrypted_body_json_length;
    request_body_json = malloc(request_body_json_length);

    encrypted_request_body_json_length = cecies_calc_base64_length(cecies_curve448_calc_output_buffer_needed_size(request_body_json_length));
    encrypted_request_body_json = malloc(encrypted_request_body_json_length);

    if (request_body_json == NULL || encrypted_request_body_json == NULL)
    {
        r = 20;
        goto exit;
    }

    snprintf(request_body_json, request_body_json_length, "{\"user_id\":%zu,\"pw\":\"%s\",\"totp\":\"%s\",\"body\":\"%s\"}", ctx->user_id, pw_sha512, has_totp_set(ctx) ? ctx->user_totp : "", encrypted_body_json);

    r = cecies_curve448_encrypt((const unsigned char*)request_body_json, request_body_json_length, string2curve448key(ctx->server_public_curve448_key), encrypted_request_body_json, encrypted_request_body_json_length, &encrypted_request_body_json_length, 1);
    if (r != 0)
    {
        r = 1;
        goto exit;
    }

    sign(ctx, (const char*)encrypted_request_body_json, encrypted_request_body_json_length, sig);

    request.url = url;
    request.url_length = server_url_length + path_length;
    request.method = GLITCHEDHTTPS_POST;
    request.content = (char*)encrypted_request_body_json;
    request.content_length = encrypted_request_body_json_length;
    request.content_type = "text/plain";
    request.content_type_length = 10;

    struct glitchedhttps_header additional_headers[] = {
        { "ed25519-signature", sig },
    };

    request.additional_headers_count = 1;
    request.additional_headers = additional_headers;

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

    if (!is_valid_server_sig(ctx, pw_sha512, 128, response))
    {
        r = -10;
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
    if (encrypted_request_body_json)
    {
        mbedtls_platform_zeroize(encrypted_request_body_json, encrypted_request_body_json_length);
        free(encrypted_request_body_json);
    }
    mbedtls_platform_zeroize(url, sizeof(url));
    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(pw_sha512, sizeof(pw_sha512));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
    mbedtls_platform_zeroize(&request, sizeof(request));
    glitchedhttps_response_free(response);
    return r;
}

int opsick_client_get_server_version(struct opsick_client_user_context* ctx, char out_json[128])
{
    assert(ctx != NULL);

    int r = -1;

    const char* path = "/version";
    const size_t path_length = strlen(path);

    size_t server_url_length;
    if (!is_valid_server_url(ctx->server_url, &server_url_length) || server_url_length + path_length > OPSICK_CLIENT_MAX_URL_LENGTH)
    {
        return r;
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
        r = -2;
        goto exit;
    }

    if (!is_successful(response))
    {
        r = response->status_code;
        goto exit;
    }

    snprintf(out_json, 128, "%s", response->content);

    if (!is_valid_server_sig(ctx, response->content, response->content_length, response))
    {
        r = -10;
        goto exit;
    }

    r = 0;

exit:
    mbedtls_platform_zeroize(&request, sizeof(struct glitchedhttps_request));
    mbedtls_platform_zeroize(ctx->user_totp, sizeof(ctx->user_totp));
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