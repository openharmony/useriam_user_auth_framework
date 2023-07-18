/*
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

import display from '@ohos.display';
import screen from '@ohos.screen';
import userAuth from '@ohos.userIAM.userAuth';
import Constants, { CmdType, FingerPosition } from '../../common/vm/Constants';
import AuthUtils from '../utils/AuthUtils';
import LogUtils from '../utils/LogUtils';
import TimeUtils from '../utils/TimeUtils';
import NumKeyBoard from './NumkeyBoard';

const TAG = 'FullScreen';
const INTERVAL = 1000;
const DIGITAL_PASSWORD_IC_DIAMETER = 12;
const THOUSANDTH = 1000;
const TITLE_POSITION = 200;
const DEL_PWD = -2;
const CALL_PHONE = -1;
const GO_BACK = -3;
const DEFAULT_SIZE = 72;
const FINGER_TEXT_POSITION = 120;
const FINGER_HIGH = 72;
const FINGER_X_POSITION = 86;
const FINGER_Y_POSITION = 40;
const MAX_LENGTH = 32;
const AUTH_TYPE_FACE = 2;
const AUTH_TYPE_FINGER = 4;
const PASSWORD_LENGTH = 4;
const PASSWORD_ARRAY_LENGTH = 6;

interface ControlType {
  isSixPassword?: boolean,
  isLandscape: boolean,
  jumpFinger: boolean,
  isShowFace: boolean,
  isShowFinger: boolean,
}

interface KeyboardType {
  index: number,
  row1: string | Resource,
  row2?: string,
  value?: number,
  bkg?: boolean,
}

@Component
export default struct FullScreen {
  @Link pinSubType: string;
  @Link textValue: string;
  @Link authType: Array<userAuth.UserAuthType>;
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State pinLock: number = 0;
  @State screenClass: object = {};
  @StorageLink('cueWord') cueWord: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_use_pwd'));
  @StorageLink('passwordArray') passwordArray: string[] = [];
  @StorageLink('passwordArrayNumber') passwordArrayNumber: string[] = [];
  @State passwordObj: string = '';
  numKeyboard: KeyboardType[] = Constants.numKeyBoard;
  @State prompt: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_use_pwd'));
  @State fingerText: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
  @StorageLink('screenLockDirection') screenLockDirection: number = 1;
  @State controlType: ControlType = {
    jumpFinger: false,
    isLandscape: false,
    isSixPassword: true,
    isShowFace: this.authType.includes(AUTH_TYPE_FACE),
    isShowFinger: this.authType.includes(AUTH_TYPE_FINGER)
  }
  @State fingerPosition: FingerPosition = {
    sensorType: ''
  }
  @State screen: number[] = [];
  @State faceFingerLockArr: boolean[] = [false, false];
  @Consume isLandscape: boolean;
  @Consume underFingerPrint: boolean;

  queryScreenInfo(): void {
    try {
      screen.getAllScreens((err, data) => {
        if (err.code) {
          LogUtils.error(TAG, 'Failed to get all screens. err: ' + err.code);
          return;
        }
        this.screenClass = data[0];
      });
    } catch (error) {
      LogUtils.error(TAG, 'getAllScreens catch error: ' + error?.code);
    }
  }

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      const { type,remainAttempts, lockoutDuration,sensorInfo} = item.payload;
      switch (type) {
        case Constants.noticeTypePin:
          this.clearPassword();
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
            if (num === 'first') {
              this.prompt = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_use_pwd'));
            }
            // 3: pin Residual number
            if (remainAttempts < 3) {
              this.prompt = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try'))
              + remainAttempts + globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_frequency'));
            }
          }
          if (remainAttempts === 0 && lockoutDuration) {
            // 1: pin lock
            this.pinLock = 1;
            this.countdown(lockoutDuration);
          }

          if (!remainAttempts && !lockoutDuration) {
            // 1: pin lock
            this.pinLock = 1;
          }
          break;
        case Constants.noticeTypeFace:
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'));
            this.faceFingerLockArr[0] = false;
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
          }
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_face_forbidden'));
            this.faceFingerLockArr[0] = true;
          }
          break;
        case Constants.noticeTypeFinger:
          let sensor;
          if (sensorInfo && JSON.stringify(sensorInfo) !== '{}') {
            sensor = JSON.parse(sensorInfo);
            this.fingerPosition = sensor || { sensorType: '' };
            const displayClass = display.getDefaultDisplaySync();
            this.screen = [displayClass.width, displayClass.height];
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_use_pwd'));
          }
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
            this.fingerText = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
            if (sensor) {
              if (sensor.sensorType === 'UNDER_SCREEN_SENSOR' ||
              sensor.sensorType === 'BOTH_SENSOR' ||
              sensor.sensorType === 'SensorType1') {
                // 5: Residual number
                if (num !== 'first' && remainAttempts > 0) {
                  AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                }
              }
            }
          }
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
            this.fingerText = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
            this.faceFingerLockArr[1] = true;
          }
          break;
        default:
          LogUtils.error(TAG, 'type: ' + type);
          break;
      }
    })
  }

  aboutToAppear(): void {
    LogUtils.debug(TAG, 'aboutToAppear');
    try {
      AppStorage.SetOrCreate('passwordArray', []);
      this.queryScreenInfo();
      if (this.cmdData && this.cmdData.length > 0) {
        this.onCmdDataChange('first');
      }
      if (this.controlType.isShowFace && this.controlType.isShowFinger) {
        AuthUtils.getInstance()
          .sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace, Constants.noticeTypeFinger]);
        return;
      }
      if (this.controlType.isShowFace) {
        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
        return;
      }
    } catch (error) {
      LogUtils.error(TAG, 'aboutToAppear catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }

  clearPassword(): void {
    this.passwordArray = [];
    this.passwordArrayNumber = [];
    this.passwordArray = ['', '', '', '', '', ''];
    this.numKeyboard[11].value = GO_BACK;
    this.numKeyboard[11].row1 = globalThis.context.resourceManager
      .getStringSync($r('app.string.unified_authwidget_back'));
    this.updateStorage(() => {
    })
  }

  aboutToDisappear(): void {
    this.clearPassword();
  }

  countdown(freezingTime): void {
    const TRY_AGAIN = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_postretry'));
    let promptText: string = '';
    let freezingMillisecond = freezingTime;
    if (freezingMillisecond > 0) {
      promptText = TimeUtils.getFreezingTimeNm(freezingMillisecond, globalThis.context);
      promptText += TRY_AGAIN;
      setTimeout(this.countdown.bind(this), INTERVAL, freezingTime - INTERVAL);
    } else {
      promptText = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_use_pwd'));
      this.clearPassword();
      // 0: pin unlock
      this.pinLock = 0;
    }
    this.prompt = promptText;
  }

  updateStorage(callback): void {
    AppStorage.SetOrCreate('passwordArray', this.passwordArray);
    AppStorage.SetOrCreate('numKeyboard', this.numKeyboard);
    callback();
  }

  build() {
    if (!this.controlType.jumpFinger) {
      Column() {
        Column() {
          // 1: pin lock
          if (this.pinLock === 1) {
            Text($r('app.string.unified_authwidget_locked'))
              .margin({ bottom: $r('app.float.content_padding') })
              .fontColor($r('sys.color.ohos_id_color_primary_contrary'))
              .fontSize($r('sys.float.ohos_id_text_size_headline6'))
              .fontWeight(FontWeight.Medium)
          } else if (this.controlType.isShowFace) {
            Image($r('app.media.white_faceID'))
              .id('faceImgCustomPwd')
              .width($r('app.float.image_small'))
              .height($r('app.float.image_small'))
              .margin({ bottom: $r('app.float.content_padding') })
              .onClick(() => {
                if (!this.faceFingerLockArr[0]) {
                  this.prompt = globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                  AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
                } else {
                  this.prompt = globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_title_face_forbidden'));
                }
              })
          } else {
            Text()
              .margin({ bottom: $r('app.float.content_padding') })
              .fontColor($r('sys.color.ohos_id_color_primary_contrary'))
              .fontSize($r('sys.float.ohos_id_text_size_headline6'))
              .fontWeight(FontWeight.Medium)
          }
          Text(this.prompt)
            .id('cancelIconCustomPassword')
            .fontSize(this.prompt === globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_use_pwd'))
              ? $r('sys.float.ohos_id_text_size_body1')
              : $r('sys.float.ohos_id_text_size_body2'))
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.ohos_id_color_text_secondary_contrary'))
            .margin({ bottom: $r('app.float.margin_16') })
            .textAlign(TextAlign.Center)
            .textOverflow({ overflow: TextOverflow.None })
            .height($r('app.float.size_24'))
            .onClick(() => {
              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                this.prompt = globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
              }
            })

          Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
            // 0: pin unlock
            if (this.pinLock === 0) {
              if (this.pinSubType === Constants.pinSix) {
                List({ space: DIGITAL_PASSWORD_IC_DIAMETER }) {
                  ForEach(this.passwordArray, (item) => {
                    if ((!item || item === '') && item !== 0) {
                      ListItem() {
                        Button()
                          .border({
                            color: Color.White,
                            style: BorderStyle.Solid,
                            width: 1
                          })
                          .borderRadius($r('app.float.input_btn_size'))
                          .width($r('app.float.input_btn_size'))
                          .height($r('app.float.input_btn_size'))
                          .type(ButtonType.Circle)
                          .backgroundColor(Color.Transparent)
                      }
                      .margin({
                        left: $r('app.float.margin_12'),
                        right: $r('app.float.margin_12'),
                        top: $r('app.float.margin_14')
                      })
                    } else {
                      ListItem() {
                        Button()
                          .borderRadius($r('app.float.input_btn_size'))
                          .width($r('app.float.input_btn_size'))
                          .height($r('app.float.input_btn_size'))
                          .type(ButtonType.Circle)
                          .backgroundColor($r('sys.color.ohos_id_color_text_primary_contrary'))
                      }
                      .margin({
                        left: $r('app.float.margin_12'),
                        right: $r('app.float.margin_12'),
                        top: $r('app.float.margin_14')
                      })
                    }
                  })
                }
                .listDirection(Axis.Horizontal)
                .height($r('app.float.input_height'))

              } else if (this.pinSubType === Constants.pinNumber) {
                Stack() {
                  TextInput({ placeholder: '', text: this.passwordArrayNumber.join('') })
                    .width('100%')
                    .onChange(async (value: string) => {
                      // Removes non-numeric characters from a string
                      this.passwordArrayNumber = value.replace(/[^\d]/g, '').split('');
                    })
                    .id('pinInputNumber')
                    .onSubmit(async (enterKey: EnterKeyType) => {
                      let str = this.passwordArrayNumber.toString();
                      this.textValue = str.replace(/,/g, '');
                      if (this.passwordArrayNumber.length < PASSWORD_LENGTH) {
                        return;
                      }

                      const strData = this.passwordArrayNumber.toString();
                      this.textValue = strData.replace(/,/g, '');
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                    })
                    .type(InputType.Password)
                    .backgroundImageSize(ImageSize.Auto)
                    .visibility(Visibility.Visible)
                    .copyOption(CopyOptions.None)
                    .maxLength(MAX_LENGTH)
                }
              } else if (this.pinSubType === Constants.pinMixed) {
                TextInput({ text: this.passwordObj })
                  .height($r('app.float.btn_height'))
                  .type(InputType.Password)
                  .textAlign(TextAlign.Center)
                  .copyOption(CopyOptions.None)
                  .maxLength(MAX_LENGTH)
                  .onSubmit(async (enterKey: EnterKeyType) => {
                    // check callback
                    if (this.passwordObj.length < PASSWORD_LENGTH) {
                      return;
                    }
                    this.textValue = this.passwordObj;
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                  })
                  .onChange((value: string) => {
                    this.passwordObj = value;
                  })
                  .id('pinInput')
              }
            }
          }
          .height($r('app.float.text_high'))

          Button(($r('app.string.unified_authwidget_forgotpwd')), {
            stateEffect: false
          })
            .id('forgotBtnCustomPwd')
            .height($r('app.float.text_high'))
            .backgroundColor(Color.Transparent)
            .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
            .fontSize($r('sys.float.ohos_id_text_size_button1'))
            .fontWeight(FontWeight.Medium)
            .onClick(() => {
              let str = this.passwordArrayNumber.toString()
              this.textValue = str.replace(/,/g, '');
            })
            .visibility(Visibility.Hidden)
        }

        // 0: pin unlock
        Column() {
          if (!this.isLandscape && this.pinLock === 0 && this.pinSubType === Constants.pinSix) {
            NumKeyBoard({
              onKeyPress: (index, callback) => {
                let keyValue = this.numKeyboard[index].value;
                if (keyValue > 0 || keyValue === 0) {
                  const index = this.passwordArray.map(item => item).indexOf('')
                  if (index > -1) {
                    this.passwordArray[index] = keyValue + '';
                    this.numKeyboard[11].row1 = $r('app.string.unified_authwidget_delete');
                    this.numKeyboard[11].value = DEL_PWD;
                    if (index === 5) {
                      this.passwordArray[index] = keyValue + '';
                      if (this.passwordArray.join('').length < PASSWORD_ARRAY_LENGTH) {
                        return;
                      }
                      let str = this.passwordArray.toString();
                      this.textValue = str.replace(/,/g, '');
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                    }
                    this.updateStorage(callback);
                  }
                } else if (keyValue === DEL_PWD) {
                  const index = this.passwordArray.map(item => item).indexOf('');
                  if (index === -1) {
                    this.passwordArray[5] = '';
                  } else if (index === 1) {
                    this.passwordArray[index - 1] = '';
                    this.numKeyboard[11].value = GO_BACK;
                    this.numKeyboard[11].row1 = globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_back'));
                  } else {
                    this.passwordArray[index - 1] = '';
                  }
                  this.updateStorage(callback);
                } else if (keyValue === GO_BACK) {
                  // 0: pin unlock
                  this.pinLock = 0;
                  this.clearPassword();
                  globalThis.session?.terminateSelf?.();
                } else if (keyValue === CALL_PHONE) {
                  if (this.passwordArray.join('').length < PASSWORD_ARRAY_LENGTH) {
                    return;
                  }

                  let str = this.passwordArray.toString();
                  this.textValue = str.replace(/,/g, '');
                  AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                }
              }
            })
          } else {
            Text().height(Constants.fullContainerHeight)
          }
        }
        .width(Constants.fullContainerWidth)
        .height('40%')

        // 1: pin lock
        Column() {
          if (this.controlType.isShowFinger && this.pinLock !== 1) {
            if (this.fingerPosition.sensorType !== 'OUT_OF_SCREEN_SENSOR'
            && this.fingerPosition.sensorType !== 'NON_SENSOR') {
              if (this.fingerPosition.sensorType === 'UNDER_SCREEN_SENSOR' ||
              this.fingerPosition.sensorType === 'BOTH_SENSOR' ||
              this.fingerPosition.sensorType === 'SensorType1') {
                if (this.fingerPosition.udSensorCenterYInThousandth /
                this.screen[1] > Constants.fingerSensorPositionLine &&
                !this.isLandscape) {
                  Image($r('app.media.ic_unlock_fingerprint'))
                    .id('fingerprintImgCustomPassword')
                    .width(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .height(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .position({
                      x: px2vp(this.fingerPosition.udSensorCenterXInThousandth),
                      y: px2vp(this.fingerPosition.udSensorCenterYInThousandth)
                    })
                    .onClick(() => {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    })
                } else {
                  Image($r('app.media.finger_white'))
                    .id('fingerWhiteImgCustomPassword')
                    .width($r('app.float.image_back_size'))
                    .height($r('app.float.image_back_size'))
                    .margin({ top: $r('app.float.input_btn_size') })
                    .onClick(() => {
                      if (this.isLandscape) {
                        this.underFingerPrint = true;
                      } else {
                        this.controlType.jumpFinger = true;
                        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                      }
                    })
                }
              }
            }
          }
        }.width($r('app.float.digital_password_mask_height'))
        .height(this.controlType.isShowFinger ? $r('app.float.finger_high') : '9%')
        .justifyContent(FlexAlign.Start)
      }
      .justifyContent(FlexAlign.End)
      .width(Constants.fullContainerWidth)
    } else if (!this.controlType.isLandscape) {
      Column() {
        Text(globalThis.wantParams?.title)
          .id('titleFullScreen')
          .height($r('app.float.text_high'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontSize($r('sys.float.ohos_id_text_size_sub_title2'))
          .fontWeight(FontWeight.Medium)
          .position({ y: TITLE_POSITION })
          .width('100%')
          .textAlign(TextAlign.Center)
        Text(this.fingerText)
          .height($r('app.float.text_high'))
          .fontColor($r('sys.color.ohos_id_color_text_secondary'))
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .position({
            y: (px2vp(this.fingerPosition.udSensorCenterYInThousandth * this.screen[1] / THOUSANDTH) -
            FINGER_TEXT_POSITION - px2vp(FINGER_HIGH + this.fingerPosition.udSensorRadiusInPx))
          })
          .width('100%')
          .textAlign(TextAlign.Center)
          .margin({ top: $r('app.float.padding_8') })
        Image($r('app.media.ic_unlock_fingerprint'))
          .id('unlockFingerprintImgCustomPwd')
            // radius
          .width(px2vp(this.fingerPosition.udSensorRadiusInPx * 2))
          .height(px2vp(this.fingerPosition.udSensorRadiusInPx * 2))
          .position({
            x: (px2vp(this.fingerPosition.udSensorCenterXInThousandth * this.screen[0] / THOUSANDTH)
            - px2vp(FINGER_X_POSITION + this.fingerPosition.udSensorRadiusInPx)),
            y: (px2vp(this.fingerPosition.udSensorCenterYInThousandth * this.screen[1] / THOUSANDTH)
            - FINGER_Y_POSITION - px2vp(DEFAULT_SIZE + this.fingerPosition.udSensorRadiusInPx))
          })
          .onClick(() => {
            if (this.prompt !== globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
              AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
            }
          })
        Button($r('app.string.unified_authwidget_cancel'), {
          type: ButtonType.Normal,
          stateEffect: true
        })
          .margin({ bottom: $r('app.float.three_hundred_size'), left: 'auto', right: 'auto' })
          .backgroundColor(Color.Transparent)
          .fontColor($r('sys.color.ohos_id_color_text_primary_contrary'))
          .onClick(() => {
            this.controlType.jumpFinger = false;
          })
      }
      .justifyContent(FlexAlign.End)
      .height('100%')
      .width('100%')
    }
  }
}