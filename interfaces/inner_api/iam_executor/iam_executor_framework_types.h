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
 * @file iam_executor_framework_types.h
 *
 * @brief Some type defines in executor framwork.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_EXECUTOR_FRAMEWORK_TYPES_H
#define IAM_EXECUTOR_FRAMEWORK_TYPES_H

#include <cstdint>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Defines authentication result.
 */
enum UserAuthResult : int32_t {
    /** Authentication result is success. */
    USERAUTH_SUCCESS = 0,
    /** Authentication result is error. */
    USERAUTH_ERROR = 1,
};

/**
 * @brief Defines Template infomation.
 */
struct TemplateInfo {
    /** Executor type. */
    uint32_t executorType;
    /** Freezing time. */
    int32_t freezingTime;
    /** Remain time. */
    int32_t remainTimes;
    /** Extra Info. */
    std::vector<uint8_t> extraInfo;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EXECUTOR_FRAMEWORK_TYPES_H
