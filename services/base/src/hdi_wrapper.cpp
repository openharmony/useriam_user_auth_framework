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

#include "hdi_wrapper.h"

#include "iam_ptr.h"
#include "iproxy_broker.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<IUserAuthInterface> HdiWrapper::GetHdiInstance()
{
    auto hdi = IUserAuthInterface::Get();
    if (!hdi) {
        return nullptr;
    }
    return Common::SptrToStdSharedPtr<IUserAuthInterface>(hdi);
}

sptr<IRemoteObject> HdiWrapper::GetHdiRemoteObjInstance()
{
    auto hdi = IUserAuthInterface::Get();
    if (!hdi) {
        return sptr<IRemoteObject>(nullptr);
    }
    return HDI::hdi_objcast<IUserAuthInterface>(hdi);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
