/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FACERECOGNITION_USER_AUTH_HELPER_H
#define FACERECOGNITION_USER_AUTH_HELPER_H

#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum AuthMethod {
    PIN_ONLY = 0xF,
    FACE_ONLY = 0xF0
};

enum Module {
    FACE_AUTH = 1
};

enum FaceTipsCode {
    FACE_AUTH_TIP_TOO_BRIGHT = 1,
    FACE_AUTH_TIP_TOO_DARK = 2,
    FACE_AUTH_TIP_TOO_CLOSE = 3,
    FACE_AUTH_TIP_TOO_FAR = 4,
    FACE_AUTH_TIP_TOO_HIGH = 5,
    FACE_AUTH_TIP_TOO_LOW = 6,
    FACE_AUTH_TIP_TOO_RIGHT = 7,
    FACE_AUTH_TIP_TOO_LEFT = 8,
    FACE_AUTH_TIP_TOO_MUCH_MOTION = 9,
    FACE_AUTH_TIP_POOR_GAZE = 10,
    FACE_AUTH_TIP_NOT_DETECTED = 11,
};

enum FingerprintTips {
    FINGERPRINT_AUTH_TIP_GOOD = 0,
    FINGERPRINT_AUTH_TIP_IMAGER_DIRTY = 1,
    FINGERPRINT_AUTH_TIP_INSUFFICIENT = 2,
    FINGERPRINT_AUTH_TIP_PARTIAL = 3,
    FINGERPRINT_AUTH_TIP_TOO_FAST = 4,
    FINGERPRINT_AUTH_TIP_TOO_SLOW = 5
};

napi_value AuthTrustLevelConstructor(napi_env env);
napi_value ResultCodeConstructor(napi_env env);
napi_value AuthenticationResultConstructor(napi_env env);
napi_value FaceTipsCodeConstructor(napi_env env);
napi_value FingerprintTipsConstructorForKits(napi_env env);
napi_value UserAuthTypeConstructor(napi_env env);
napi_value UserAuthInit(napi_env env, napi_value exports);
napi_value EnumExport(napi_env env, napi_value exports);
napi_value GetCtor(napi_env env);
napi_value GetCtorForAPI6(napi_env env);
napi_value ConstructorForAPI6(napi_env env, napi_callback_info info);
napi_value UserAuthServiceConstructor(napi_env env, napi_callback_info info);
napi_value GetVersion(napi_env env, napi_callback_info info);
napi_value GetAvailableStatus(napi_env env, napi_callback_info info);
napi_value Auth(napi_env env, napi_callback_info info);
napi_value Execute(napi_env env, napi_callback_info info);
napi_value CancelAuth(napi_env env, napi_callback_info info);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // FACERECOGNITION_USER_AUTH_HELPER_H
