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

#ifndef HDI_WRAPPER_H
#define HDI_WRAPPER_H

#include <cstdint>
#include <memory>

#include "v1_0/iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class HdiWrapper {
public:
    static std::shared_ptr<OHOS::HDI::UserAuth::V1_0::IUserAuthInterface> GetHdiInstance();
    static sptr<IRemoteObject> GetHdiRemoteObjInstance();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // HDI_WRAPPER_H