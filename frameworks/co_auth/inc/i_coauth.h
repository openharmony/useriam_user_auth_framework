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

#ifndef I_COAUTH_H
#define I_COAUTH_H

#include <iremote_broker.h>
#include <singleton.h>
#include "icoauth_callback.h"
#include "attributes.h"
#include "iexecutor_callback.h"
#include "auth_executor.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ICoAuth : public IRemoteBroker {
public:
    /* Message ID */
    enum : uint32_t {
        COAUTH_EXECUTOR_REGIST = 0,
    };

    /* Business function */
    virtual uint64_t Register(std::shared_ptr<AuthExecutor> executorInfo,
        const sptr<IExecutorCallback> &callback) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.CoAuth.ICoAuth");
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace CoAuth {
using ICoAuth = OHOS::UserIam::UserAuth::ICoAuth;
}
}
}
#endif // I_COAUTH_H