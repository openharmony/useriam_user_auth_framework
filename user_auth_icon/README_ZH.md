# 嵌入式用户身份认证控件

- [简介](#简介)
- [目录](#目录)
- [说明](#说明)
  - [接口说明](#接口说明)
- [示例](#示例)


## 简介

**嵌入式用户身份认证控件**  提供应用界面上展示的人脸、指纹认证图标，具体功能如下：

1、提供嵌入式人脸、指纹认证控件图标，可被应用集成。

2、支持自定义图标的颜色和大小，但图标样式不可变更。

3、点击控件图标后可拉起系统弹窗式人脸、指纹认证控件。


## 目录

```undefined
//base/useriam/user_auth_framework/user_auth_icon
├── library                              # library模块目录
│   ├── src/main/ets/components/mainpage # 嵌入式控件实现，入口
```


## 说明

### **嵌入式用户身份认证控件接口说明**

**表1** Icon点击事件回调接口

| 接口名  | 描述                             |
| ------ | -------------------------------- |
| onIconClick?: () => void; | 通知应用点击事件触发 |

**表2** 身份认证结果通知回调接口

| 接口名  | 描述                             |
| ------ | -------------------------------- |
| onAuthResult: (result: userAuth.UserAuthResult) => void; | 通知应用身份认证结果信息 |


## 示例

```undefined
import userAuth from '@ohos.userIAM.userAuth';
import UserAuthIcon from '@ohos.userIAM.userAuthIcon';

@Entry
@Component
struct Index {
  authParam: userAuth.AuthParam = {
    challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
    authType: [userAuth.UserAuthType.FACE, userAuth.UserAuthType.PIN],
    authTrustLevel: userAuth.AuthTrustLevel.ATL3,
  };
  widgetParam: userAuth.WidgetParam = {
    title: '请进行身份认证',
  };

  build() {
    Row() {
      Column() {
        UserAuthIcon({
          authParam: this.authParam,
          widgetParam: this.widgetParam,
          iconHeight: 200,
          iconColor: Color.Blue,
          onIconClick: () => {
            console.info("The user clicked the icon.");
          },
          onAuthResult: (result: userAuth.UserAuthResult) => {
            console.info('Get user auth result, result = ' + JSON.stringify(result));
          },
        })
      }
    }
  }
}
```
