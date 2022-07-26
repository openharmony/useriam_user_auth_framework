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

#ifndef IAUTH_DRIVER_HDI_H
#define IAUTH_DRIVER_HDI_H

#include <cstdint>

#include "iremote_broker.h"

#include "iauth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IAuthDriverHdi {
public:
    IAuthDriverHdi() = default;
    virtual ~IAuthDriverHdi() = default;

    virtual void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAUTH_DRIVER_HDI_H