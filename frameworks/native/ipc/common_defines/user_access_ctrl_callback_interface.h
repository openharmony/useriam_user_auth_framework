/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef USER_ACCESS_CTRL_CALLBACK_INTERFACE_H
#define USER_ACCESS_CTRL_CALLBACK_INTERFACE_H

#include <cstdint>

#include "iremote_broker.h"

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum UserAccessCtrlCallbackInterfaceCode : uint32_t {
    ON_VERIFY_TOKEN_RESULT = 0,
};

class VerifyTokenCallbackInterface : public IRemoteBroker {
public:
    /*
     * returns token plaintext information.
     */
    virtual void OnVerifyTokenResult(int32_t result, const Attributes &attributes) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIam.UserAccessCtrl.VerifyTokenCallback");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CALLBACK_INTERFACE_H