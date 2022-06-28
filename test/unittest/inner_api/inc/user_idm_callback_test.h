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

#ifndef USER_IDM_CALLBACK_TEST_H
#define USER_IDM_CALLBACK_TEST_H

#include "common_info.h"
#include "user_idm_defines.h"
#include "user_idm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class GetInfoCallbackUT : public GetInfoCallback {
public:
    virtual ~GetInfoCallbackUT() = default;
    void OnGetInfo(std::vector<CredentialInfo> &info) override;
};

class GetSecInfoCallbackUT : public GetSecInfoCallback {
public:
    virtual ~GetSecInfoCallbackUT() = default;
    void OnGetSecInfo(SecInfo &info)override;
};

class IDMCallbackUT : public IdmCallback {
public:
    virtual ~IDMCallbackUT() = default;
    void OnResult(int32_t result, RequestResult reqRet) override;
    void OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet) override;
};
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS

#endif // USER_IDM_CALLBACK_TEST_H