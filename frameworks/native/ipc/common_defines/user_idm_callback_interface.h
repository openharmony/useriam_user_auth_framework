/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "idm_callback_interface_ipc_interface_code.h"
#include "idm_get_cred_info_callback_interface_ipc_interface_code.h"
#include "idm_get_secure_user_info_callback_interface_ipc_interface_code.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmGetCredInfoCallbackInterface : public IRemoteBroker {
public:
    /*
     * return all registered credential information.
     */
    virtual void OnCredentialInfos(const std::vector<CredentialInfo> &credInfoList) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetInfoCallback");
};

class IdmGetSecureUserInfoCallbackInterface : public IRemoteBroker {
public:
    /*
     * return all registered security information.
     */
    virtual void OnSecureUserInfo(const SecUserInfo &secUserInfo) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetSecInfoCallback");
};

class IdmCallbackInterface : public IamCallbackInterface {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IIDMCallback");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CALLBACK_INTERFACE_H