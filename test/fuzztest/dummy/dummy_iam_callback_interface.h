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

#ifndef DUMMY_IAM_CALLBACK_INTERFACE_H
#define DUMMY_IAM_CALLBACK_INTERFACE_H

#include "iam_callback_interface.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyIamCallbackInterface : public IamCallbackInterface {
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {};
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override
    {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_IAM_CALLBACK_INTERFACE_H