/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_CHECK_H
#define IAM_CHECK_H

#include "iam_logger.h"

namespace OHOS {
namespace UserIam {
namespace Common {
// these macros are used to check condition that should never fail
#define IF_FALSE_LOGE_AND_RETURN(cond)                  \
    do {                                                \
        if (!(cond)) {                                  \
            IAM_LOGE("(" #cond ") check fail, return"); \
            return;                                     \
        }                                               \
    } while (0)

#define IF_FALSE_LOGE_AND_RETURN_VAL(cond, retVal)      \
    do {                                                \
        if (!(cond)) {                                  \
            IAM_LOGE("(" #cond ") check fail, return"); \
            return (retVal);                            \
        }                                               \
    } while (0)
} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_CHECK_H