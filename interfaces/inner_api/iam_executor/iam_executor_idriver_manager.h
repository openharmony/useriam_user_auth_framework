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

#ifndef IAM_EXECUTOR_IDRIVER_MANAGER_H
#define IAM_EXECUTOR_IDRIVER_MANAGER_H

#include <cstdint>
#include <map>

#include "iam_executor_iauth_driver_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/**
 * @brief Hardware device interface config.
 */
struct HdiConfig {
    /** Driver ID. */
    uint16_t id; // non-zero
    /** The current driver. */
    std::shared_ptr<IAuthDriverHdi> driver;
};

class IDriverManager {
public:
    /**
     * @brief Default constructor.
     */
    IDriverManager() = default;

    /**
     * @brief Deconstructor.
     */
    virtual ~IDriverManager() = default;

    /**
     * @brief Start.
     *
     * @param hdiName2Config Hardware device interface name and config.
     * @return Return the result success or not.
     */
    static int32_t Start(const std::map<std::string, HdiConfig> &hdiName2Config);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EXECUTOR_IDRIVER_MANAGER_H