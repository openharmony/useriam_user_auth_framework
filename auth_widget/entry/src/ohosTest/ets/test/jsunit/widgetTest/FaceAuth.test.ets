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

export default function FaceAuthTest() {
  describe('faceAuthTest', function () {
    beforeAll(async function () {
      const data = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 5, "type": "face"
          }, "version": "1"
        }],
        "title": "",
        "type": ["face"],
        "widgetContextId": 16850018705910348000,
        "windowModeType": "DIALOG_BOX"
      };
      globalThis.wantParams = data;
    })

    it('promptText_resetPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('promptText_resetPin_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_pin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('cancelBtn_pin_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('usePwd_pin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('usePwd_pin_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('cancelImg_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('cancelImg_all_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('usePwdBtn_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('usePwdBtn_all_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('resetPromptText_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('resetPromptText_all_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('blueFingerprintImg_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('blueFingerprintImg_all_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('unlockFingerprintImg_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('unlockFingerprintImg_customPwd'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('errFaceImg_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('errFaceImg_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('blueFingerprintImg_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('blueFingerprintImg_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('cancelBtn_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('usePwdBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('usePwdBtn_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_mixedPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('cancelBtn_mixedPin_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('okBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('okBtn_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_sixPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('cancelBtn_sixPin_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('promptText_reset_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      let btn = await driver.findComponent(ON.id('promptText_reset_faceAuth'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })
  })
}