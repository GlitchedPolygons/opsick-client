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

#include <time.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @file opsick-client.h
 * @author Raphael Beck
 * @brief Opsick client library for communicating with Opsick servers.
 */

/**
 * @mainpage Opsick Client Library - API Documentation
 * @section intro Introduction
 * TODO: document this!
 * @section install Installation
 * See the git repository's [README.md](https://github.com/GlitchedPolygons/opsick-client) for instructions on how to get started with this.
 * @section usage Usage
 * TODO: write this section here!
 * <p> Also: check out the {@link #opsick_client_return_code} enum to find out what each of the functions' exit codes means!
 */

/**
 * Opsick client library version number (<strong>MAJOR</strong>).
 */
#define OPSICK_CLIENT_VERSION_MAJOR 2

/**
 * Opsick client library version number (<strong>MINOR</strong>).
 */
#define OPSICK_CLIENT_VERSION_MINOR 0

/**
 * Opsick client library version number (<strong>PATCH</strong>).
 */
#define OPSICK_CLIENT_VERSION_PATCH 0

/**
 * @brief An enumeration containing all possible return values that the opsick client library may use (starting from major version \c 2 upwards).
 */
enum opsick_client_return_code
{
    /**
     * Return code of a successful opsick client function execution.
     */
    OPSICK_CLIENT_SUCCESS = 0,

    /**
     * Return code for generic failures within the library.
     */
    OPSICK_CLIENT_FAILURE = 1,

    /**
     * This is returned when any invalid argument(s) were passed into an opsick client function.
     */
    OPSICK_CLIENT_INVALID_ARGS = 2,

    /**
     * Uh oh...
     */
    OPSICK_CLIENT_OUT_OF_MEMORY = 3,

    /**
     * This return code is returned if a function call was made without having called {@link #opsick_client_init()} at least once.
     */
    OPSICK_CLIENT_UNINITIALIZED = 10,

    /**
     * This error code describes library initialization failures.
     * \see {@link #opsick_client_init()}
     */
    OPSICK_CLIENT_INIT_FAILED = 11,

    /**
     * Returned when the used server URL is invalid.
     */
    OPSICK_CLIENT_INVALID_SERVER_URL = 20,

    /**
     * Returned when the used server URL is too long.
     */
    OPSICK_CLIENT_SERVER_URL_TOO_LONG = 21,

    /**
     * This error code describes a failure to connect to the established opsick URL.
     */
    OPSICK_CLIENT_CONNECTION_TO_SERVER_FAILED = 22,

    /**
     * Returned if things got weird.... (connection to the server OK but server doesn't seem to be an Opsick server).
     */
    OPSICK_CLIENT_CONNECTION_TO_SERVER_WEIRD = 23,

    /**
     * Error code for when submission of the HTTP request to the Opsick server failed.
     */
    OPSICK_CLIENT_REQUEST_SUBMISSION_TO_SERVER_FAILED = 24,

    /**
     * Returned if the server's response was not in a valid format.
     */
    OPSICK_CLIENT_INVALID_SERVER_RESPONSE_FORMAT = 30,

    /**
     * Returned if the server's signature couldn't be verified against its response (uh oh...)
     */
    OPSICK_CLIENT_INVALID_SERVER_RESPONSE_SIGNATURE = 31,

    /**
     * Manual key regeneration not performed due to either failure or not being necessary yet.
     */
    OPSICK_CLIENT_KEY_REGEN_NOT_PERFORMED = 40,

    /**
     * Operation failed due to the used opsick_client_user_context not containing private keys.
     */
    OPSICK_CLIENT_MISSING_PRIVATE_KEYS = 50,

    /**
     * This error code is returned when symmetric encryption using pwcrypt failed.
     */
    OPSICK_CLIENT_PWCRYPT_ENCRYPTION_FAILED = 60,

    /**
     * Symmetric decryption using pwcrypt failed (e.g. wrong password).
     */
    OPSICK_CLIENT_PWCRYPT_DECRYPTION_FAILED = 61,

    /**
     * Error code for when the asymmetric encryption of the message for the server failed.
     */
    OPSICK_CLIENT_CECIES_ENCRYPTION_FAILED = 70,

    /**
     * This is returned if asymmetric decryption of the server's response failed.
     */
    OPSICK_CLIENT_CECIES_DECRYPTION_FAILED = 71,
};

/**
 * Opsick user profile containing parameters for requests to the opsick server as well as the user's actual data fields.
 */
struct opsick_client_user_context
{
    /**
     * The opsick server base URL, including the protocol (<c>http://</c> or <c>https://</c>). <p>
     * NUL-terminated string.
     */
    char server_url[1024];

    /**
     * The opsick server's public Ed25519 key as a hex-encoded, NUL-terminated string. <p>
     * Use this to verify the server's response signatures!
     */
    char server_public_ed25519_key[64 + 1];

    /**
     * The opsick server's public Curve448 key (hex-encoded, NUL-terminated string). <p>
     * Encrypt your requests to the server with this key!
     */
    char server_public_curve448_key[112 + 1];

    /**
     * User account ID.
     */
    uint64_t id;

    /**
     * TOTP (2FA token) - if applicable.    <p>
     * NUL-terminated string.               <p>
     * Typically, this will be a NUL-terminated 6-digits string. <p>
     * Fill this with \p 0x00 if you wish to omit this parameter! <p>
     * This will be reset by all endpoint request functions on exit, even in case of failure!
     */
    char totp[6 + 1];

    /**
     * User account password.
     */
    char pw[1024];

    /**
     * The Unix timestamp of when the user account was created.
     */
    uint64_t iat_utc;

    /**
     * The Unix timestamp of when the user account will expire/has expired.
     */
    uint64_t exp_utc;

    /**
     * The Unix timestamp of when the user account was last accessed (e.g. sent new data to the server).
     */
    uint64_t lastmod_utc;

    /**
     * The user's private ed25519 key as a hex-encoded, NUL-terminated string. <p>
     * This is used to sign requests for the server.
     */
    char user_private_ed25519_key[128 + 1];

    /**
     * The user's public ed25519 key as a hex-encoded, NUL-terminated string. <p>
     * This is used by the server to verify this user's requests to it.
     */
    char user_public_ed25519_key[64 + 1];

    /**
     * The user's private curve448 key as a hex-encoded, NUL-terminated string. <p>
     * This is used to decrypt server responses (the server encrypts all responses for each user individually using his or her public key).
     */
    char user_private_curve448_key[112 + 1];

    /**
     * The user's public curve448 key as a hex-encoded, NUL-terminated string. <p>
     * This is used by the server to encrypt responses for this user.
     */
    char user_public_curve448_key[112 + 1];

    /**
     * Unix timestamp of the last key refresh for this user context.
     */
    time_t last_server_key_refresh;
};

/**
 * Initializes the opsick client library, allocating all the required resources.
 * @return Whether or not initialization failed. \c 0 means success; anything else is a failure.
 */
OPSICK_CLIENT_API int opsick_client_init();

/**
 * Frees the opsick client library, releasing all the allocated resources associated with it.
 * \warning Absolutely make sure to <strong>ALWAYS</strong> call this only after there are absolutely <strong>NO MORE</strong> pending opsick client requests!
 * Only call this once you're truly sure that you're done using the library!
 * @return \c 0
 */
OPSICK_CLIENT_API int opsick_client_free();

/**
 * Tests the connection to an opsick server.
 * @param server_url The opsick server base URL.
 * @return
 * * \p OPSICK_CLIENT_SUCCESS on success <br>
 * * \p OPSICK_CLIENT_INVALID_SERVER_URL in case of an invalid \p server_url (these require explicit \p http:// or \p https:// protocol prefix and <strong>NO trailing slashes</strong>!) <br>
 * * \p OPSICK_CLIENT_SERVER_URL_TOO_LONG in case the \p server_url exceeds the maximum allowed number of characters. <br>
 * * \p OPSICK_CLIENT_CONNECTION_TO_SERVER_FAILED if connection couldn't be established successfully. <br>
 * * \p OPSICK_CLIENT_CONNECTION_TO_SERVER_WEIRD if the connection to the URL was OK but the server is... weird... it kinda doesn't seem to be an opsick server... <br>
 * * (if none of the above {@link #opsick_client_return_code} return codes are returned, the HTTP response status code is returned)
 */
OPSICK_CLIENT_API int opsick_client_test_connection(const char* server_url);

/**
 * Fetches the currently active server public keys (ed25519 and curve448).
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_get_server_public_keys(struct opsick_client_user_context* ctx);

/**
 * Submits a password change request to the opsick server.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * @param new_pw The new user password.
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_post_passwd(struct opsick_client_user_context* ctx, const char* new_pw);

/**
 * Fetches a user account from an opsick server:
 * pass your current encrypted body's SHA2-512 (hex-encoded, NUL-terminated string) to prevent unnecessary traffic in case you already have the latest version!
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * * user_private_curve448_key: #opsick_client_user_context.user_private_curve448_key
 * @param body_sha512 The current local machine's body SHA2-512 (of the encrypted body ciphertext).
 * @param out_body_json Output string where the downloaded user body will be written into (this will be allocated if there was a newer body upstream, or set to \p NULL if the local one is already the most recent one).
 * @param out_body_json_length Where to write the decrypted output user body json's string length into.
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_get_user(struct opsick_client_user_context* ctx, const char* body_sha512, char** out_body_json, size_t* out_body_json_length);

/**
 * Fetches a user's public keys and encrypted private keys from the server db.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_get_userkeys(struct opsick_client_user_context* ctx);

/**
 * Regenerates fresh Ed25519 and Curve448 keypairs for the user and submits them to the opsick backend for immediate replacement.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * @param additional_entropy [OPTIONAL] Additional entropy to use for key generation. Pass \p NULL if you want to omit this parameter!
 * @param additional_entropy_length [OPTIONAL] Length of the passed \p additional_entropy buffer (ignored if \p additional_entropy is <c>NULL</c>).
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_regen_userkeys(struct opsick_client_user_context* ctx, const void* additional_entropy, size_t additional_entropy_length);

/**
 * Submits a user deletion request to the opsick server. Careful with this: it's irreversible!
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_post_userdel(struct opsick_client_user_context* ctx);

/**
 * Enable, disable or verify two-factor authentication for an opsick user.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * * user_private_curve448_key: #opsick_client_user_context.user_private_curve448_key (if \p action is \p 1).
 * @param action \p 0 = Disable 2FA <br> \p 1 = Enable 2FA <br> \p 2 = Verify 2FA token
 * @param out_json Where to write any output json into (must be at least 256 bytes of writable \p char buffer). <br>
 * This will only be touched if \p action is \p 1 (it will contain the generated user 2FA secret and other useful metadata to display to the user <strong>ONCE</strong>).
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_post_user2fa(struct opsick_client_user_context* ctx, int action, char out_json[256]);

/**
 * Submits a new body to the opsick server.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * * server_public_ed25519_key: #opsick_client_user_context.server_public_ed25519_key
 * * server_public_curve448_key: #opsick_client_user_context.server_public_curve448_key
 * * id: #opsick_client_user_context.id <br>
 * * totp: #opsick_client_user_context.totp (if user has 2FA enabled).
 * * pw: #opsick_client_user_context.pw
 * * user_private_ed25519_key: #opsick_client_user_context.user_private_ed25519_key
 * @param body_json The new body json to encrypt using the user's password and submit to the opsick backend.
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_post_userbody(struct opsick_client_user_context* ctx, const char* body_json);

/**
 * Fetches the opsick server version information.
 * @param ctx Required fields inside the #opsick_client_user_context struct: <br>
 * * server_url: #opsick_client_user_context.server_url <br>
 * @param out_json Where to write the fetched server version metadata json into (must be at least 128 bytes of writable \p char buffer).
 * @return
 * * {@link #opsick_client_return_code} or the returned HTTP status code representing the error (in case of a failure that is not mapped to the return code enum).
 */
OPSICK_CLIENT_API int opsick_client_get_server_version(struct opsick_client_user_context* ctx, char out_json[128]);

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
