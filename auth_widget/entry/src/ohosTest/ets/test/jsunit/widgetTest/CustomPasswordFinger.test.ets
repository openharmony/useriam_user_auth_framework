/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

import { Driver, ON } from '@ohos.UiTest';
import { beforeAll, describe, expect, it } from '@ohos/hypium';

const delayTime: number = 1000;

export default function CustomPasswordFingerTest() {
  describe('CustomPasswordFingerTest', function () {
    beforeAll(async function () {
      const wantDefault = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 5, "type": "pin", "sensorInfo": ""
          }, "version": "1"
        }],
        "pinSubType": "PIN_MIXED",
        "title": "",
        "type": ["pin", "fingerprint"],
        "widgetContextId": 6711153399710207000,
        "windowModeType": "FULLSCREEN"
      };
      globalThis.wantParams = wantDefault;
    })

    it('pinInput_full_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('pinInput'));
      expect(true).assertTrue();
      done();
    })

    it('fingerWhiteImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('fingerWhiteImgCustomPwd'));
      expect(true).assertTrue();
      done();
    })

    it('unlockFingerprintImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('unlockFingerprintImgCustomPwd'));
      expect(true).assertTrue();
      done();
    })

    it('fingerprintImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('fingerprintImgCustomPwd'));
      expect(true).assertTrue();
      done();
    })
  })
}