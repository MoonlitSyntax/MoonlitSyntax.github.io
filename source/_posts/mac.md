---
title: mac
date: 2023-08-02 17:34:27
categories:
- 系统优化设置
tags:
- Mac
description: |
    Mac一些好用的软件或设置
---

### 外接键盘键位的映射

~~想念qk100的每一天~~

#### 安装karabiner-elements

##### command、control、option的映射

![改变映射](/img/keyboard.png)

##### shift映射成`ctrl+space`

```json
{
  "title": "Custom Modifications",
  "rules": [
    {
      "description": "Change shift to ctrl",
      "manipulators": [
        {
          "type": "basic",
          "from": {
            "key_code": "left_shift",
            "modifiers": {
              "optional": ["any"]
            }
          },
          "to": [
            {
              "key_code": "left_control"
            }
          ]
        }
      ]
    }
  ]
}
```json
{
  "title": "Custom Modifications",
  "rules": [
    {
      "description": "Change left_shift alone to ctrl-space, keep shift functionality",
      "manipulators": [
        {
          "type": "basic",
          "from": {
            "key_code": "left_shift",
            "modifiers": {
              "optional": ["any"]
            }
          },
          "to_if_alone": [
            {
              "key_code": "spacebar",
              "modifiers": ["left_control"]
            }
          ],
          "to": [
            {
              "key_code": "left_shift"
            }
          ]
        }
      ]
    }
  ]
}
```

### 安装应用已损坏

```text
sudo xattr -r -d com.apple.quarantine /绝对路径
```

### fisher

有毒

`curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source && fisher install jorgebucaran/fisher`

令人窒息

好像是~~Ubuntu~~的原因 fish版本的原因

ubuntu fish

```bash
sudo apt-add-repository ppa:fish-shell/release-3
sudo apt update
sudo apt install fish
```



[Debian](https://software.opensuse.org/download.html?project=shells%3Afish&package=fish)fish安装地址

`fisher install IlanCosman/tide@v5`

### docker

#### ctfd(艰难)

最后还是docker-compose救了我

frps/frpc 好难aaaaa

#### 出题

`docker buildx build --platform linux/amd64 -t spirit001 . `amd!!!!!!!

`docker tag spirit111:latest dionysus13931/spirit111:latest`标记

`docker push dionysus13931/spirit111:latest`推送

`docker build -t dionysus19391/spirit001:latest . && docker push dionysus19391/spirit001:latest`

### 抓本地包

Firefox默认不允许抓本地包，打开 `about:config` 页面，搜索 `network.proxy.allow_hijacking_localhost` 双击变为true即可

### 密钥登录远程服务器

- `ssh-keygen`
- `cat /ssh/ssh-key-for-yun.pub`
- 登录远程服务器
- `mkdir -p ~/.ssh`
- `echo "YOUR_PUBLIC_KEY_CONTENT" >> ~/.ssh/authorized_keys`
- `chmod 700 ~/.ssh` `chmod 600 ~/.ssh/authorized_keys`

