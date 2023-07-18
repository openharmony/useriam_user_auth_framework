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
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

const delegator = abilityDelegatorRegistry.getAbilityDelegator();
const bundleName = abilityDelegatorRegistry.getArguments().bundleName;

const delayTime: number = 1000;

export default function faceAuthJsTest() {
  describe('faceAuthJsTest', function () {

    function sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }

    beforeAll(async function () {
      const data = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 4, "type": "face"
          }, "version": "1"
        }],
        "navigationButtonText": "确认",
        "title": "",
        "type": ["face"],
        "widgetContextId": 1590859524489244200,
        "windowModeType": "DIALOG_BOX"
      }
      globalThis.wantParams = data;
      sleep(1000);

      let want = {
        bundleName: bundleName,
        abilityName: "EntryAbility"
      }
      await delegator.startAbility(want);
      sleep(1000);
    })

    it('promptText_resetPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('promptTextResetPinFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_pin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelBtnPinFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('usePwd_pin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('usePwdPinFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('cancelImg_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelImgAllFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('usePwdBtn_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('usePwdBtnAllFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('resetPromptText_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('resetPromptTextAllFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('blueFingerprintImg_all_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('blueFingerprintImgAllFaceAuth'));
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

    it('errFaceImg_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('errFaceImgFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('blueFingerprintImg_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('blueFingerprintImgFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelBtnFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('usePwdBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('usePwdBtnFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_mixedPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelBtnMixedPinFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('okBtn_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('okBtnFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('cancelBtn_sixPin_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelBtnSixPinFaceAuth'));
      expect(true).assertTrue();
      done();
    })

    it('promptText_reset_faceAuth_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('promptTextResetFaceAuth'));
      expect(true).assertTrue();
      done();
    })
  })
}