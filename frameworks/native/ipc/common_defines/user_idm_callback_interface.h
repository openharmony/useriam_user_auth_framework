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
#include "iam_common_defines.h"
#include "iam_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmGetCredInfoCallbackInterface : public IRemoteBroker {
public:
    enum {
        ON_GET_INFO = 0,
    };
    class CredentialInfo {
    public:
        virtual ~CredentialInfo() = default;
        virtual uint64_t GetCredentialId() const = 0;
        virtual int32_t GetUserId() const = 0;
        virtual uint64_t GetExecutorIndex() const = 0;
        virtual uint64_t GetTemplateId() const = 0;
        virtual AuthType GetAuthType() const = 0;
        virtual uint32_t GetExecutorSensorHint() const = 0;
        virtual uint32_t GetExecutorMatcher() const = 0;
    };
    /*
     * return all registered credential information.
     */
    virtual void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetInfoCallback");
};

class IdmGetSecureUserInfoCallbackInterface : public IRemoteBroker {
public:
    enum {
        ON_GET_SEC_INFO = 0,
    };
    class EnrolledInfo {
    public:
        virtual ~EnrolledInfo() = default;
        virtual AuthType GetAuthType() const = 0;
        virtual int32_t GetUserId() const = 0;
        virtual uint64_t GetEnrolledId() const = 0;
    };

    class SecureUserInfo {
    public:
        virtual ~SecureUserInfo() = default;
        virtual int32_t GetUserId() const = 0;
        virtual PinSubType GetPinSubType() const = 0;
        virtual uint64_t GetSecUserId() const = 0;
        virtual std::vector<std::shared_ptr<EnrolledInfo>> GetEnrolledInfo() const = 0;
    };
    /*
     * return all registered security information.
     */
    virtual void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetSecInfoCallback");
};

class IdmCallbackInterface : public IamCallbackInterface {
public:
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