# useriam_userauth

- [简介](#简介)
- [目录](#目录)
- [编译构建](#编译构建)
  - [准备](#准备)
  - [获取源码](#获取源码)
  - [编译构建](#编译构建)

- [说明](#说明)
  - [接口说明](#接口说明)
  - [使用说明](#使用说明)
- [相关仓](#相关仓)


## 简介

**统一用户认证（userauth）**是用户IAM子系统的基础部件之一，对外提供统一用户身份认证功能，并且开放生物特征认证API给三方应用调用。

**图1** 统一用户认证架构图

<img src="figures/统一用户认证架构图.png" alt="口令认证架构图" style="zoom:80%;" />



用户认证接口支持针对目标用户完成达到目标认证结果可信等级（ATL）的用户身份认证。其中目标ATL由业务指定，目标用户id可以由业务指定（系统服务或系统基础应用），也可以从系统上下文获取（三方应用）。

## 目录

```undefined
//base/user_iam/user_auth
├── ohos.build			# 组件描述文件
├── userauth.gni		# 构建配置
├── frameworks			# 框架代码
├── interfaces			# 对外接口存放目录
│   ├── innerkits		# 对内部子系统暴露的头文件，供系统服务使用
│   └── kits			# 对三方应用暴露的头文件
├── sa_profile			# Service Ability 配置文件
├── services			# Service Ability 服务实现
├── test				# 测试代码存放目录
└── utils				# 测试代码存放目录
```

## 编译构建


### 准备

开发者需要在Linux上搭建编译环境：

-   [Ubuntu编译环境准备](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-lite-env-setup-linux.md)
-   Hi3518EV300单板：参考[环境搭建](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-lite-steps-hi3518-setting.md)
-   Hi3516DV300单板：参考[环境搭建](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-lite-steps-hi3516-setting.md)

### 获取源码

在Linux服务器上下载并解压一套源代码，源码获取方式参考[源码获取](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/get-code/sourcecode-acquire.md)。

### 编译构建

开发者开发第一个应用程序可参考：

-   [helloworld for Hi3518EV300](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-lite-steps-hi3518-running.md)

-   [helloworld for Hi3516DV300](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-lite-steps-hi3516-running.md)


## 说明

### 接口说明

**表1** API

| 接口名  | 描述                             |
| ------ | -------------------------------- |
| getAvailabeStatus(authType : AuthType, authTrustLevel : AuthTurstLevel) : number; | 指定ATL，查询是否支持目标认证方式 |
| auth(challenge: BigInt, authType : AuthType, authTrustLevel: AuthTurstLevel, callback: IUserAuthCallback): BigInt; | 指定ATL和认证方式，完成用户身份认证 |

### 使用说明

厂商在对接统一用户认证框架时，需要在可信执行环境中实现以下两个功能点：

1. 认证方案生成：根据目标用户录入的认证凭据和目标认证安全等级，决策用户身份认证方案；
2. 认证结果评估：根据执行器返回的身份认证结果，评估是否达到目标认证安全等级。

## 相关仓

[useriam_coauth](https://gitee.com/openharmony-sig/useriam_coauth)

[useriam_useridm](https://gitee.com/openharmony-sig/useriam_useridm)

**[useriam_userauth](https://gitee.com/openharmony-sig/useriam_userauth)**

[useriam_pinauth](https://gitee.com/openharmony-sig/useriam_pinauth)

[useriam_faceauth](https://gitee.com/openharmony/useriam_faceauth)

