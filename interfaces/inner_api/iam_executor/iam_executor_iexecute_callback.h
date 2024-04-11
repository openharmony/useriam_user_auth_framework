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
 * @file iam_executor_idriver_manager.h
 *
 * @brief Driver manager of executor.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_EXECUTOR_IEXECUTE_CALLBACK_H
#define IAM_EXECUTOR_IEXECUTE_CALLBACK_H

#include <cstdint>
#include <vector>

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IExecuteCallback {
public:
    using ResultCode = UserIam::UserAuth::ResultCode;

    /**
     * @brief Default constructor.
     */
    IExecuteCallback() = default;

    /**
     * @brief Deconstructor.
     */
    virtual ~IExecuteCallback() = default;

    /**
     * @brief The callback return execute result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about execute.
     */
    virtual void OnResult(ResultCode result, const std::vector<uint8_t> &extraInfo) = 0;

    /**
     * @brief The callback return execute result.
     *
     * @param result The result success or error code{@link ResultCode}.
     */
    virtual void OnResult(ResultCode result) = 0;

    /**
     * @brief The callback return authenticate acquire information.
     *
     * @param acquireInfo Acquire info needed to be pass in.
     * @param extraInfo Other related information about execute.
     */
    virtual void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) = 0;

    /**
     * @brief The callback send message information.
     *
     * @param destRole Destination role.
     * @param msg Message.
     */
    virtual void OnMessage(int destRole, const std::vector<uint8_t> &msg) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EXECUTOR_EXECUTE_CALLBACK_H