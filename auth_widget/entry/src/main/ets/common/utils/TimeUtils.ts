/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

export class TimeUtils {
  getFreezingTimeNm(freezingMillisecond: number, context: Context): string {
    const MINUTE_NM = context?.resourceManager?.getStringSync($r('app.string.unified_authwidget_minutes'));
    const SECOND_NM = context?.resourceManager?.getStringSync($r('app.string.unified_authwidget_seconds'));
    const ONE_MINUTE = 60;
    const RATE = 1000;
    let minute = Math.floor(freezingMillisecond / (ONE_MINUTE * RATE));
    let second = Math.round((freezingMillisecond % (ONE_MINUTE * RATE)) / RATE);
    let timeName = '';
    if (minute !== 0) {
      timeName += minute + MINUTE_NM;
    }
    if (second !== 0 && minute < 1) {
      timeName += second + SECOND_NM;
    }
    return timeName;
  }
}

let mTimeUtils = new TimeUtils();

export default mTimeUtils as TimeUtils;
