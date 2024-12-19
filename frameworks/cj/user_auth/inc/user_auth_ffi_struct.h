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

#ifndef USER_AUTH_FFI_STRUCT_H
#define USER_AUTH_FFI_STRUCT_H

#include <functional>

#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct CjAuthParam {
    uint8_t *challenge;
    int64_t challengeLen;
    uint32_t *authTypes;
    int64_t authTypesLen;
    uint32_t authTrustLevel;
    bool isReuse;
    uint32_t reuseMode;
    uint64_t reuseDuration;
};

struct CjWidgetParam {
    const char *title;
    const char *navigationButtonText;
};

struct CjUserAuthResult {
    int32_t result;
    uint8_t *token;
    int64_t tokenLen;
    uint32_t authType;
    uint64_t credentialDigest;
    uint16_t credentialCount;
};

class CjUserAuthCallback final : public AuthenticationCallback {
public:
    CjUserAuthCallback() = default;
    explicit CjUserAuthCallback(const std::function<void(CjUserAuthResult)> &onResult) : onResult_(onResult) {}
    virtual ~CjUserAuthCallback() = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::function<void(CjUserAuthResult)> onResult_;
};

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_FFI_STRUCT_H
