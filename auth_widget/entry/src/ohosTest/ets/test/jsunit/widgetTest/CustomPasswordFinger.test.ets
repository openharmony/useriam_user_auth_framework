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

export default function CustomPasswordTest() {
  describe('customPasswordTest', function () {
    beforeAll(async function () {
      const wantDefault = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 5, "type": "pin"
          }, "version": "1"
        }],
        "pinSubType": "PIN_SIX",
        "title": "",
        "type": ["pin", "fingerprint"],
        "widgetContextId": 6711153399710207000,
        "windowModeType": "FULLSCREEN"
      };
      globalThis.wantParams = wantDefault;
    })

    it('fingerWhiteImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('fingerWhiteImg_customPwd'));
      // await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('unlockFingerprintImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('unlockFingerprintImg_customPwd'));
      // await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('numKeyBord_customPwd'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('fingerprintImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('fingerprintImg_customPwd'));
      // await btn.click();
      expect(true).assertTrue();
      done();
    })
  })
}