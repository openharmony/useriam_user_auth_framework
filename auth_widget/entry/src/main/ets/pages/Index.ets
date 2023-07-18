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

import screen from '@ohos.screen';
import userAuth from '@ohos.userIAM.userAuth';
import { DialogType } from '../common/module/DialogType';
import FuncUtils from '../common/utils/FuncUtils';
import LogUtils from '../common/utils/LogUtils';
import Constants, { CmdType } from '../common/vm/Constants';
import CustomPassword from './components/CustomPassword';
import FaceAuth from './components/FaceAuth';
import FingerprintAuth from './components/FingerprintAuth';
import PasswordAuth from './components/PasswordAuth';

const DEFAULT_SIZE = 72;
const FIVE_SECOND = 5000;
const LAND_SCAPE = 2;
const TAG = 'Index';
let userAuthWidgetMgr;

@Entry
@Component
struct Index {
  @State authType: Array<userAuth.UserAuthType> = [userAuth.UserAuthType.PIN];
  @State type: string[] = [];
  @State topHeight: number = DEFAULT_SIZE;
  @State bottomHeight: number = DEFAULT_SIZE;
  @State pinSubType: string = Constants.pinNumber;
  @State dialogType: DialogType = DialogType.ALL;
  @State windowModeType: string = 'DIALOG_BOX';
  @State cmdData: Array<CmdType> = [];
  @Provide isLandscape: boolean = false;
  @Provide underFingerPrint: boolean = false;
  @State loadFlag: boolean = false;

  onScreenChange(): void {
    try {
      screen.getAllScreens((err, data) => {
        if (err.code) {
          LogUtils.error(TAG, 'Failed to get all screens. err: ' + err.code);
          globalThis.session?.terminateSelf();
          return;
        }
        LogUtils.debug(TAG, ' get all screens. result:-- ' + JSON.stringify(data));
        this.isLandscape = data[0].orientation === LAND_SCAPE;
        LogUtils.debug(TAG, 'globalThis.wantParams： ' + JSON.stringify(globalThis.wantParams));
        if (globalThis.wantParams) {
          this.getParams(globalThis.wantParams);
          this.handleAuthStart();
          this.cmdData = globalThis.wantParams?.cmd;
        } else {
          LogUtils.error(TAG, 'aboutToAppear wantParams null');
          globalThis.session?.terminateSelf();
        }
        if (this.isLandscape && this.underFingerPrint) {
          setTimeout(() => {
            globalThis.session?.terminateSelf();
          }, FIVE_SECOND)
        } else {
          this.loadFlag = true;
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'getAllScreens catch error: ' + error?.code);
      globalThis.session?.terminateSelf();
    }
  }

  handleAuthStart(): void {
    LogUtils.info(TAG, 'handleAuthStart');
    try {
      userAuthWidgetMgr = userAuth.getUserAuthWidgetMgr(Constants.userAuthWidgetMgrVersion);
      LogUtils.info(TAG, 'getUserAuthWidgetMgr success');
      let that = this;
      userAuthWidgetMgr.on('command', {
        callback: function (result) {
          LogUtils.info(TAG, 'userAuthWidgetMgr onCommand result: ' + JSON.stringify(result));
          const cmdDataObj = JSON.parse(result?.cmdData || '{}');
          if (cmdDataObj?.cmd?.[0]?.payload?.result === Constants.userAuthWidgetMgrSuccess) {
            globalThis.session?.terminateSelf();
          } else {
            that.cmdData = cmdDataObj?.cmd || [];
            that.pinSubType = cmdDataObj?.pinSubType;
            that.handleIsUnder(cmdDataObj?.cmd || []);
          }
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'getUserAuthWidgetMgr catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }

  handleIsUnder(cmd: Array<CmdType>): void {
    try {
      LogUtils.info(TAG, 'handleIsUnder');
      cmd?.length > 0 && cmd.map((item) => {
        const { type, sensorInfo } = item?.payload;
        if (type === Constants.noticeTypeFinger) {
          if (sensorInfo && JSON.stringify(sensorInfo) !== '{}') {
            const fingerPosition = JSON.parse(sensorInfo);
            if (fingerPosition?.sensorType === 'UNDER_SCREEN_SENSOR' ||
            fingerPosition?.sensorType === 'BOTH_SENSOR' ||
            fingerPosition?.sensorType === 'SensorType1') {
              this.underFingerPrint = true;
            }
          }
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'handleIsUnder catch error: ' + error?.code);
    }
  }

  aboutToAppear(): void {
    LogUtils.debug(TAG, 'aboutToAppear');
    this.onScreenChange();
  }

  aboutToDisappear(): void {
    LogUtils.info(TAG, 'aboutToDisappear');
    if (userAuthWidgetMgr) {
      userAuthWidgetMgr.off('command', {
        callback: function (result) {
          LogUtils.info(TAG, 'aboutToDisappear userAuthWidgetMgr offCommand result: ' + JSON.stringify(result));
        }
      });
    }
  }

  getParams(result): void {
    LogUtils.info(TAG, 'getParams');
    LogUtils.info(TAG, 'dengjiewen msg test');
    const { pinSubType, windowModeType, cmd, type, widgetContextId } = result;
    this.pinSubType = pinSubType;
    const newType = type && type.map(item => {
      switch (item) {
        case Constants.noticeTypePin:
          return userAuth.UserAuthType.PIN;
        case Constants.noticeTypeFinger:
          return userAuth.UserAuthType.FINGERPRINT;
        case Constants.noticeTypeFace:
          return userAuth.UserAuthType.FACE;
      }
    })
    globalThis.widgetContextId = widgetContextId;
    this.authType = newType;
    this.type = type;
    this.windowModeType = windowModeType;
    this.dialogType = FuncUtils.getDialogType(newType);
    this.cmdData = cmd || [];
    this.handleIsUnder(cmd || []);
  }

  build() {
    Column() {
      if (this.isLandscape && this.underFingerPrint) {
        Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.End }) {
          Column() {
            Text(globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_tip_verify_in_portrait_mode')))
              .fontColor($r('sys.color.ohos_id_color_text_primary_contrary'))
              .fontSize($r('sys.float.ohos_id_text_size_body2'))
              .fontWeight(FontWeight.Regular)
          }
          .backgroundColor($r('sys.color.ohos_id_color_instant_tip_bg'))
          .borderRadius($r('sys.float.ohos_id_corner_radius_default_l'))
          .padding({
            left: $r('app.float.padding_16'),
            top: $r('app.float.padding_8'),
            right: $r('app.float.padding_16'),
            bottom: $r('app.float.padding_8')
          })
          .margin({ bottom: $r('app.float.margin_64') })
        }
        .width(Constants.fullContainerWidth)
        .height(Constants.fullContainerHeight)
      } else if (this.loadFlag) {
        Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.SpaceAround, alignItems: ItemAlign.Center }) {
          if ('DIALOG_BOX' === this.windowModeType) {
            if (this.authType.includes(userAuth.UserAuthType.FACE)) {
              FaceAuth({
                type: $windowModeType,
                pinSubType: $pinSubType,
                dialogType: $dialogType,
                cmdData: $cmdData,
              })
            } else if (this.authType.includes(userAuth.UserAuthType.FINGERPRINT)) {
              FingerprintAuth({
                type: $windowModeType,
                pinSubType: $pinSubType,
                dialogType: $dialogType,
                cmdData: $cmdData,
              })
            } else {
              PasswordAuth({
                pinSubType: $pinSubType,
                cmdData: $cmdData
              })
            }
          } else {
            // full screen PIN
            CustomPassword({
              authType: $authType,
              pinSubType: $pinSubType,
              cmdData: $cmdData,
            })
          }
        }
      }
    }.onAreaChange(() => {
      FuncUtils.getWindowHeight();
    })
  }
}