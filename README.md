# DuoduoDiag — 多多买菜门店端真机诊断 tweak

诊断型 Theos tweak，注入 `com.aimi.store`（进程 `AMStation`），记录反调试/完整性相关调用与环境快照，输出到设备文件用于回传分析。

## 目录结构

- `Tweak.xm` — hook 实现
- `control` / `Makefile` / `DuoduoDiag.plist` — Theos 打包与 bundle 过滤
- `.github/workflows/build-deb.yml` — GitHub Actions 自动构建 deb
- `export_diag.sh` — 设备端导出脚本

## 本机到 GitHub

1. 将本目录初始化为独立仓库并推送：

`__bash
cd E:\mi15pro\duoduo\ios-tweak
git init
git add .
git commit -m "init duoduo diagnostic tweak"
git remote add origin <你的仓库地址>
git branch -M main
git push -u origin main
`

2. 推送后 `.github/workflows/build-deb.yml` 自动触发；也可在 Actions 页手动 `Run workflow`。
3. 构建完成后在 Artifacts 下载 `DuoduoDiag-deb`。

## 真机安装

越狱设备（Substrate 或 ElleKit 已装）：

`__bash
scp DuoduoDiag_0.0.1_iphoneos-arm.deb root@<设备IP>:/var/tmp/
ssh root@<设备IP>
dpkg -i /var/tmp/DuoduoDiag_0.0.1_iphoneos-arm.deb
killall -9 AMStation 2>/dev/null
`

## 采集诊断

1. 打开多多买菜门店端，登录并触发你之前被限制的功能。
2. 在设备上执行导出：

`__bash
bash export_diag.sh
`

3. 回传 `/var/mobile/Documents/duoduo_diag_export.txt`（或原始 `duoduo_diag.log`）。

## 当前 hook 点

- `sysctl` / `sysctlbyname` — 记录调用名与返回值
- `UIApplication didFinishLaunchingWithOptions:` — 环境快照
- 环境快照含：bundle id、版本、`volantis.*` 字段、URL schemes、entitlements、签名信息、越狱/Frida 迹象

## 下一步扩展

拿到真实日志后，根据调用的 sysctl name 和出现的风控特征，继续追加 `SecTrust*`、`pthread_introspection_hook_install` 以及具体业务类的 hook。
