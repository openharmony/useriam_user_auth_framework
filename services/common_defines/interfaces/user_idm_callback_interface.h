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

#ifndef USER_IDM_CALLBACK_INTERFACE_H
#define USER_IDM_CALLBACK_INTERFACE_H

#include <optional>

#include "iremote_broker.h"

#include "attributes.h"
#include "credential_info.h"
#include "iam_types.h"
#include "secure_user_info.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmGetCredInfoCallbackInterface : public IRemoteBroker {
public:
    /*
     * return all registered credential information.
     */
    virtual void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) = 0;

    enum {
        ON_GET_INFO = 0,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetInfoCallback");
};

class IdmGetSecureUserInfoCallbackInterface : public IRemoteBroker {
public:
    /*
     * return all registered security information.
     */
    virtual void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) = 0;

    enum {
        ON_GET_SEC_INFO = 0,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetSecInfoCallback");
};

class IdmCallbackInterface : public IRemoteBroker {
public:
    /*
     * return result code and additional information through callback.
     */
    virtual void OnResult(int32_t result, const Attributes &reqRet) = 0;

    /*
     * return result code and additional information through acquire info.
     */
    virtual void OnAcquireInfo(int32_t module, int32_t acquire, const Attributes &reqRet) = 0;

    enum {
        IDM_CALLBACK_ON_RESULT = 0,
        IDM_CALLBACK_ON_ACQUIRE_INFO,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IIDMCallback");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CALLBACK_INTERFACE_H