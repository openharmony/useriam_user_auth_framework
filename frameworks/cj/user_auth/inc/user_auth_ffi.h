/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_FFI_H
#define USER_AUTH_FFI_H

#include "user_auth_ffi_struct.h"

#include "user_auth_common_defines.h"

using OHOS::UserIam::UserAuth::CAuthParam;
using OHOS::UserIam::UserAuth::CUserAuthResult;
using OHOS::UserIam::UserAuth::CWidgetParam;
using OHOS::UserIam::UserAuth::EnrolledState;
using OHOS::UserIam::UserAuth::UserAuthCallbackCj;

#define FFI_EXPORT __attribute__((visibility("default")))

extern "C" {
FFI_EXPORT int32_t FfiUserAuthGetAvailableStatus(uint32_t authType, uint32_t authTrustLevel);

FFI_EXPORT int32_t FfiUserAuthGetEnrolledState(uint32_t authType, EnrolledState *enrolledState);

FFI_EXPORT UserAuthCallbackCj *FfiUserAuthNewCb(void (*callback)(CUserAuthResult));

FFI_EXPORT void FfiUserAuthDeleteCb(const UserAuthCallbackCj *callbackPtr);

FFI_EXPORT uint64_t FfiUserAuthStart(const CAuthParam &authParam, const CWidgetParam &widgetParam,
    UserAuthCallbackCj *callbackPtr);

FFI_EXPORT int32_t FfiUserAuthCancel(uint64_t contextId);
}


#endif // USER_AUTH_FFI_H
