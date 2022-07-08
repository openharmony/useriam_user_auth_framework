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

#ifndef USER_IDM_CALLBACK_H
#define USER_IDM_CALLBACK_H

#include "common_info.h"
#include "user_idm_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class GetInfoCallback {
public:
    virtual void OnGetInfo(std::vector<CredentialInfo> &info) = 0;
};

class GetSecInfoCallback {
public:
    virtual void OnGetSecInfo(SecInfo &info) = 0;
};

class IdmCallback {
public:
    virtual void OnResult(int32_t result, RequestResult reqRet) = 0;
    virtual void OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using GetInfoCallback = OHOS::UserIam::UserAuth::GetInfoCallback;
using GetSecInfoCallback = OHOS::UserIam::UserAuth::GetSecInfoCallback;
using IdmCallback = OHOS::UserIam::UserAuth::IdmCallback;
}
}
}
namespace OHOS {
namespace UserIAM {
namespace UserIDM {
using GetInfoCallback = OHOS::UserIam::UserAuth::GetInfoCallback;
using GetSecInfoCallback = OHOS::UserIam::UserAuth::GetSecInfoCallback;
}
}
}
#endif // USER_IDM_CALLBACK_H