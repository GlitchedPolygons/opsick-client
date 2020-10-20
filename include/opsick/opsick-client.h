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

#ifndef OPSICK_CLIENT_H
#define OPSICK_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(OPSICK_CLIENT_DLL)
#ifdef OPSICK_CLIENT_BUILD_DLL
#define OPSICK_CLIENT_API __declspec(dllexport)
#else
#define OPSICK_CLIENT_API __declspec(dllimport)
#endif
#else
#define OPSICK_CLIENT_API
#endif

#include <stdint.h>

/**
 * @file opsick-client.h
 * @author Raphael Beck
 * @brief Opsick client library for communicating with Opsick servers.
 */

/**
 * Opsick client library version number (<strong>MAJOR</strong>).
 */
#define OPSICK_CLIENT_VERSION_MAJOR 1

/**
 * Opsick client library version number (<strong>MINOR</strong>).
 */
#define OPSICK_CLIENT_VERSION_MINOR 0

/**
 * Opsick client library version number (<strong>PATCH</strong>).
 */
#define OPSICK_CLIENT_VERSION_PATCH 0

/**
 * User request profile containing parameters for requests to the opsick server.
 */
struct opsick_client_user_request_params
{
    /**
     * The opsick server base URL, including the protocol (<c>http://</c> or <c>https://</c>). <p>
     * NUL-terminated string.
     */
    char server_url[1024];

    /**
     * User account ID.
     */
    uint64_t user_id;

    /**
     * TOTP (2FA token) - if applicable.    <p>
     * NUL-terminated string.               <p>
     * Typically, this will be a NUL-terminated 6-digits string. <p>
     * Fill this with \p 0x00 if you wish to omit this parameter!
     */
    char user_totp[6 + 1];

    /**
     * User account password.
     */
    char user_pw[512];

    /**
     * The user's private ed25519 key as a hex-encoded, NUL-terminated string. <p>
     * This is used to sign requests for the server.
     */
    char user_private_ed25519_key[128 + 1];

    /**
     * The user's private curve448 key as a hex-encoded, NUL-terminated string. <p>
     * This is used to decrypt server responses (the server encrypts all responses for each user individually using his or her public key).
     */
    char user_private_curve448_key[112 + 1];
};

/**
 * Tests the connection to an opsick server.
 * @param server_url The opsick server base URL.
 * @return
 * * \p 0 on success <br>
 * * \p -1 if connection couldn't be established successfully.
 */
OPSICK_CLIENT_API int opsick_client_test_connection(const char* server_url);

/**
 * Fetches the currently active server public keys (ed25519 and curve448).
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url
 * @param out_server_ed25519_pubkey_hexstr Where to write the fetched server ed25519 public key into (writable \p char array of at least 65 bytes: 64 characters + 1 NUL-terminator).
 * @param out_server_curve448_pubkey_hexstr Where to write the fetched server curve448 public key into (writable \p char array of at least 113 bytes: 112 characters + 1 NUL-terminator).
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_get_server_public_keys(const struct opsick_client_user_request_params* user_profile, char out_server_ed25519_pubkey_hexstr[64 + 1], char out_server_curve448_pubkey_hexstr[112 + 1]);

/**
 * Submits a password change request to the opsick server.
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * * user_private_ed25519_key: #opsick_client_user_request_params.user_private_ed25519_key
 * @param new_pw The new user password.
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_post_passwd(const struct opsick_client_user_request_params* user_profile, const char* new_pw);

/**
 * Fetches a user account from an opsick server:
 * pass your current encrypted body's SHA2-512 (hex-encoded, NUL-terminated string) to prevent unnecessary traffic in case you already have the latest version!
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * * user_private_ed25519_key: #opsick_client_user_request_params.user_private_ed25519_key
 * * user_private_curve448_key: #opsick_client_user_request_params.user_private_curve448_key
 * @param body_sha512 The current local machine's body SHA2-512 (of the encrypted body ciphertext).
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_get_user(const struct opsick_client_user_request_params* user_profile, const char* body_sha512); // TODO: decide on output

/**
 * Fetches a user's public keys and encrypted private keys from the server db.
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * @return
 */
OPSICK_CLIENT_API int opsick_client_get_userkeys(const struct opsick_client_user_request_params* user_profile); // TODO: decide on output

/**
 * Submits a user deletion request to the opsick server. Careful with this: it's irreversible!
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * * user_private_ed25519_key: #opsick_client_user_request_params.user_private_ed25519_key
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_post_userdel(const struct opsick_client_user_request_params* user_profile);

/**
 * Enable, disable or verify two-factor authentication for an opsick user.
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * * user_private_ed25519_key: #opsick_client_user_request_params.user_private_ed25519_key
 * * user_private_curve448_key: #opsick_client_user_request_params.user_private_curve448_key (if \p action is \p 1).
 * @param action \p 0 = Disable 2FA <br> \p 1 = Enable 2FA <br> \p 2 = Verify 2FA token
 * @param out_json Where to write any output json into (must be at least 256 bytes of writable \p char buffer). <br>
 * This will only be touched if \p action is \p 1 (it will contain the generated user 2FA secret and other useful metadata to display to the user <strong>ONCE</strong>).
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_post_user2fa(const struct opsick_client_user_request_params* user_profile, int action, char out_json[256]);

/**
 * Submits a new body to the opsick server.
 * @param user_profile Required fields inside the #opsick_client_user_request_params struct: <br>
 * * server_url: #opsick_client_user_request_params.server_url <br>
 * * user_id: #opsick_client_user_request_params.user_id <br>
 * * user_totp: #opsick_client_user_request_params.user_totp (if user has 2FA enabled).
 * * user_pw: #opsick_client_user_request_params.user_pw
 * * user_private_ed25519_key: #opsick_client_user_request_params.user_private_ed25519_key
 * @param body_json The new body json to encrypt using the user's password and submit to the opsick backend.
 * @return
 * * \p 0 on success <br>
 * * \p 1 if encryption failed <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_post_userbody(const struct opsick_client_user_request_params* user_profile, const char* body_json);

/**
 * Fetches the opsick server version information.
 * @param out_json Where to write the fetched server version metadata json into (must be at least 128 bytes of writable \p char buffer).
 * @return
 * * \p 0 on success <br>
 * * The returned HTTP status code representing the error in case of a failure.
 */
OPSICK_CLIENT_API int opsick_client_get_server_version(char out_json[128]);

/**
 * Gets the version number of the opsick client library currently in use.
 * @param out_version_string [OPTIONAL] Writable \p char buffer of \p 16 or more bytes into which to write the human-readable version of the current opsick client library version in use (<strong>MAJOR.MINOR.PATCH</strong>). <br>
 * Pass \p NULL if you want to omit this and only return the MAJOR version number \p int
 * @return Opsick client library version number (<strong>MAJOR</strong>).
 */
OPSICK_CLIENT_API int opsick_client_get_client_version(char out_version_string[16]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CLIENT_H