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

OPSICK_CLIENT_API int opsick_client_get_server_public_keys(char out_ed25519_pubkey_hextstr[64 + 1], char out_curve448_pubkey_hextstr[112 + 1]);

OPSICK_CLIENT_API int opsick_client_post_passwd();

OPSICK_CLIENT_API int opsick_client_get_userget();

OPSICK_CLIENT_API int opsick_client_post_userdel();

OPSICK_CLIENT_API int opsick_client_post_user2fa();

OPSICK_CLIENT_API int opsick_client_post_userbody();

OPSICK_CLIENT_API int opsick_client_get_server_version();

OPSICK_CLIENT_API int opsick_client_get_client_version();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CLIENT_H