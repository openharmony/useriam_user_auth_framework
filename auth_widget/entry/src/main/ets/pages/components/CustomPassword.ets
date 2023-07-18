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

import account_osAccount from '@ohos.account.osAccount';
import userAuth from '@ohos.userIAM.userAuth';
import FullScreen from '../../common/components/FullScreen';
import FuncUtils from '../../common/utils/FuncUtils';
import LogUtils from '../../common/utils/LogUtils';
import Constants from '../../common/vm/Constants';

const TAG = 'CustomPassword';
const BLUR_OPACITY = 0.5;
const SATURATE = 1.3;
const BLUR_RADIUS = 242;
const BACK_BLUR = 80;
const PADDING_ZERO = 0;
let pinAuthManager;
let pinData = '';

@Component
export default struct CustomPassword {
  @Link pinSubType: string;
  @Link authType: Array<userAuth.UserAuthType>;
  @Link cmdData: [];
  @State isBackTouched: boolean = false
  @State @Watch('onTextValueChange') textValue: string = '';
  @Consume isLandscape: boolean;
  @StorageLink('SYSTEM_STATUS_BAR_HEIGHT') SYSTEM_STATUS_BAR_HEIGHT: number = 0;
  @StorageLink('SYSTEM_NAVIGATION_BAR_HEIGHT') SYSTEM_NAVIGATION_BAR_HEIGHT: number = 0;

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  aboutToAppear(): void {
    try {
      LogUtils.info(TAG, 'aboutToAppear PINAuth');
      pinAuthManager = new account_osAccount.PINAuth();
      // register input
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          LogUtils.info(TAG, 'aboutToAppear registerInputer onGetData');
          const uint8PW = FuncUtils.getUint8PW(pinData);
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'aboutToAppear PINAuth catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }

  aboutToDisappear(): void {
    LogUtils.info(TAG, 'aboutToDisappear PINAuth unregisterInputer');
    pinAuthManager?.unregisterInputer?.();
  }

  build() {
    Column() {
      Column() {
      }
      .width(Constants.fullContainerWidth)
      .height(Constants.fullContainerWidth)
      .position({ x: 0, y: 0 })
      .opacity(BLUR_OPACITY)
      .backgroundColor($r('app.color.full_screen_background'))
      .blur(BLUR_RADIUS)
      .saturate(SATURATE)

      Column() {
        Flex({ direction: FlexDirection.Row }) {
          Image($r('app.media.ic_white_cancel'))
            .id('cancelImgCustomPwd')
            .width($r('app.float.image_back_size'))
            .height($r('app.float.image_back_size'))
            .margin({ left: $r('sys.float.ohos_id_max_padding_start'), top: $r('app.float.content_padding') })
            .backgroundColor(this.isBackTouched
              ? $r('sys.color.ohos_id_color_hover') : Color.Transparent)
            .onClick(() => {
              globalThis.session?.terminateSelf?.();
            })
            .onTouch((event: TouchEvent) => {
              if (event.type === TouchType.Down) {
                this.isBackTouched = true;
              }
              if (event.type === TouchType.Up) {
                this.isBackTouched = false;
              }
            });
        }

        GridRow({
          columns: 8,
          gutter: { x: 5, y: 10 },
          breakpoints: { value: Constants.deviceDpi,
            reference: BreakpointsReference.WindowSize },
          direction: GridRowDirection.Row
        }) {
          GridCol({ span: { xs: 0, sm: 1, md: 1, lg: 1 } })
            .visibility(Visibility.Hidden)
          GridCol({
            span: { xs: 8, sm: 6, md: 6, lg: 6 },
          }) {
            FullScreen({
              textValue: $textValue,
              authType: $authType,
              pinSubType: $pinSubType,
              cmdData: $cmdData
            })
          }
        }
      }
      .padding(this.isLandscape
        ? PADDING_ZERO
        : { top: this.SYSTEM_STATUS_BAR_HEIGHT, bottom: this.SYSTEM_NAVIGATION_BAR_HEIGHT })
      .justifyContent(FlexAlign.SpaceBetween)
      .width(Constants.fullContainerWidth)
      .height(Constants.fullContainerWidth)
    }
    .width(Constants.fullContainerWidth)
    .height(Constants.fullContainerWidth)
    .backdropBlur(BACK_BLUR)
  }
}