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

#include "user_auth_ffi.h"

using namespace OHOS::UserIam::UserAuth;

void UserAuthCallbackCj::OnAcquireInfo(const int32_t module, const uint32_t acquireInfo, const Attributes &extraInfo) {
    (void) module;
    (void) acquireInfo;
    (void) extraInfo;
}

void UserAuthCallbackCj::OnResult(const int32_t result, const Attributes &extraInfo) {
    if (this->onResult_ == nullptr) {
        return;
    }

    std::vector<uint8_t> token;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    int32_t authType{0};
    extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);

    CUserAuthResult ret = {
        .result = result,
        .token = token.data(),
        .tokenLen = token.size(),
        .authType = static_cast<uint32_t>(authType),
    };

    extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, ret.credentialDigest);
    extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, ret.credentialCount);

    this->onResult_(ret);
}
