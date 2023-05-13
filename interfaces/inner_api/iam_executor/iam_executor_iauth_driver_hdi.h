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

/**
 * @file iam_executor_iauth_driver_hdi.h
 *
 * @brief Hardware device interface for authenticate driver.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_EXECUTOR_IAUTH_DRIVER_HDI_H
#define IAM_EXECUTOR_IAUTH_DRIVER_HDI_H

#include <cstdint>

#include "iremote_broker.h"

#include "iam_executor_iauth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IAuthDriverHdi {
public:
    /**
     * @brief Default constructor.
     */
    IAuthDriverHdi() = default;

    /**
     * @brief Deconstructor.
     */
    virtual ~IAuthDriverHdi() = default;

    /**
     * @brief Get the list of executor.
     *
     * @param executorList The list of executor.
     */
    virtual void GetExecutorList(std::vector<std::shared_ptr<UserAuth::IAuthExecutorHdi>> &executorList) = 0;

    /**
     * @brief On hdi disconnect.
     */
    virtual void OnHdiDisconnect() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EXECUTOR_IAUTH_DRIVER_HDI_H