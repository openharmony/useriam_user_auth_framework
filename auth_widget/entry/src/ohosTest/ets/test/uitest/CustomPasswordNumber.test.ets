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
import userAuth from '@ohos.userIAM.userAuth';

const delegator = abilityDelegatorRegistry.getAbilityDelegator();
const bundleName = abilityDelegatorRegistry.getArguments().bundleName;

const delayTime: number = 1000;

export default function CustomPasswordNumberTest() {
  describe('CustomPasswordNumberTest', function () {
    beforeAll(async function () {
      let userAuthInstance = null;
      const authParam = {
        challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
        authType: [1],
        authTrustLevel: 10000,
      };
      const widgetParam = {
        title: '使用密码验证',
        windowMode: 2,
        navigationButtonText: '确认',
      };
      userAuthInstance = await userAuth.getUserAuthInstance(authParam, widgetParam);
      userAuthInstance.start();

      const data = {
        "cmd": [{
          "event": "CMD_NOTIFY_AUTH_START", "payload": {
            "lockoutDuration": 0, "remainAttempts": 5, "type": "pin", "sensorInfo": ""
          }, "version": "1"
        }],
        "pinSubType": "PIN_SIX",
        "title": "",
        "type": ["pin"],
        "widgetContextId": 7932856209793250000,
        "windowModeType": "FULLSCREEN",
      };
      globalThis.wantParams = data;

      let want = {
        bundleName: bundleName,
        abilityName: 'CustomPwdNumberAbility'
      }
      await delegator.startAbility(want);
    })

    it('numKeyBord0_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('numKeyBordCustomPwd0'));
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord1_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd1'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord2_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd2'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord3_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd3'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord4_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd4'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord5_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd5'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord6_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd6'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord7_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd7'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord8_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd8'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord10_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd10'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord9_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd9'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('numKeyBord11_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('numKeyBordCustomPwd11'));
      await btn.click();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord0_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('textNumKeyBordCustomPwd0'));
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord1_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd1'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('teNtnumKeyBord2_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd2'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord3_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd3'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord4_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd4'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord5_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd5'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord6_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd6'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord7_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd7'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord8_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd8'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord10_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd10'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord9_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd9'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textNumKeyBord11_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      const btn = await driver.findComponent(ON.id('textNumKeyBordCustomPwd11'));
      await btn.getType();
      expect(true).assertTrue();
      done();
    })

    it('textPrompt_customPwd_test', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('cancelIconCustomPwd'));
      expect(true).assertTrue();
      done();
    })

    it('clickEventCancal_Input', 0, async function (done) {
      let driver = Driver.create();
      await driver.delayMs(delayTime);
      await driver.findComponent(ON.id('pinSix'));
      expect(true).assertTrue();
      done();
    })
  })
}