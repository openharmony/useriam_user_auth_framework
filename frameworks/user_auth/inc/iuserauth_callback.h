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

#ifndef IUSERAUTH_CALLBACK_H
#define IUSERAUTH_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_object.h>
#include "userauth_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class IUserAuthCallback : public IRemoteBroker {
public:
    /*
     * returns the acquireinfo.
     */
    virtual void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) = 0;

    /*
     * returns the authentication result.
     */
    virtual void onAuthResult(const int32_t result, const AuthResult &extraInfo) = 0;

    /*
     * returns the identification result.
     */
    virtual void onIdentifyResult(const int32_t result, const IdentifyResult &extraInfo) = 0;

    /*
     * returns executor property information, such as remaining authentication times and remaining freezing time.
     */
    virtual void onExecutorPropertyInfo(const ExecutorProperty &result) = 0;

    /*
     * returns a number value indicating whether the property setting was successful.
     */
    virtual void onSetExecutorProperty(const int32_t result) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIAM.UserAuth.IUserAuthCallback");
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // IUSERAUTH_CALLBACK_H
