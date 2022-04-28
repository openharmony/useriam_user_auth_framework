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

#ifndef IUSERIDM_CALLBACK_H
#define IUSERIDM_CALLBACK_H

#include <iremote_broker.h>
#include "useridm_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class IGetInfoCallback : public IRemoteBroker {
public:
    /*
     * return all registered credential information.
     */
    virtual void OnGetInfo(std::vector<CredentialInfo> &info) = 0;

    enum {
        ON_GET_INFO = 0,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetInfoCallback");
};

class IGetSecInfoCallback : public IRemoteBroker {
public:
    /*
     * return all registered security information.
     */
    virtual void OnGetSecInfo(SecInfo &info) = 0;

    enum {
        ON_GET_SEC_INFO = 0,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IGetSecInfoCallback");
};

class IIDMCallback : public IRemoteBroker {
public:

    /*
     * return result code and additional information through callback.
     */
    virtual void OnResult(int32_t result, RequestResult reqRet) = 0;

    /*
     * return result code and additional information through acquireinfo.
     */
    virtual void OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet) = 0;

    enum {
        IDM_CALLBACK_ON_RESULT = 0,
        IDM_CALLBACK_ON_ACQUIRE_INFO,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.useridm.IIDMCallback");
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // IUSERIDM_CALLBACK_H