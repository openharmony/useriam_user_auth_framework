/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MATCHING_SKILLS_H
#define MATCHING_SKILLS_H

#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace EventFwk {
using Want = OHOS::AAFwk::Want;

class MatchingSkills : public Parcelable {
public:
    MatchingSkills() {};
    MatchingSkills(const MatchingSkills &matchingSkills) {};
    ~MatchingSkills() {};

    virtual bool Marshalling(Parcel &parcel) const override
    {
        return false;
    };
    void AddEvent(const std::string &event) {};
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // MATCHING_SKILLS_H