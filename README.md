# decipher

decipher 是一个基于 Go 语言编写的高性能本地哈希解密工具。它利用预计算（彩虹表原理）的方式，通过构建本地哈希缓存库来实现快速的哈希查找与解密。支持多种常见的哈希算法，并内置了常用的弱口令字典。

## 1. 功能介绍

*   **高性能解密**: 利用 Go 语言的并发特性，快速进行哈希计算和匹配。
*   **静态哈希算法**: 内置 30+ 种静态哈希算法，涵盖 MD5, SHA 系列, MySQL, NTLM, MSSQL等。
*   **动态哈希算法**: 支持bcrypt等明文和密文无对应关系的动态hash算法等。
*   **解密算法支持**: 支持BASE64、DES、AES等某些CMS的密码解密算法。
*   **预计算缓存解密**: 支持将自定义字典和内置字典预先计算为哈希表（Cache），极大提升后续的解密速度。
*   **动态计算解密**: 支持运行时动态验证哈希值，无需预计算所有可能的哈希组合。
*   **Salt支持**: 支持带 Salt 的哈希计算和解密，可灵活配置 Salt 组合模式。
*   **内置字典**: 仅集成部分简单常用弱口令，更多字典需要用户添加。
*   **算法猜测**: 支持通过hash和salt解密从而实现算法猜测。
*   **结果导出**: 支持将解密结果导出为 CSV 文件。

## 2. 算法列表 20260302
提示: 目前已实现cmd5.com加密列表中的所有加密算法示例
```
Available algorithms:
  1:  base64
  2:  des_crmeb_admin
  3:  md5
  4:  md5_middle
  5:  md5(md5($pass))
  6:  md5(md5($pass).NiuCloud)
  7:  md5(md5(md5($pass)))
  8:  md5(unicode($pass))
  9:  base64(md5($pass))
  10:  md5($pass.$salt)
  11:  md5($salt.$pass)
  12:  md5($salt.$pass.$salt)
  13:  md5($salt.md5($pass))
  14:  md5(md5($salt).$pass)
  15:  md5($pass.md5($salt))
  16:  md5(md5($pass).$salt)
  17:  md5(md5($salt).md5($pass))
  18:  md5(md5($pass).md5($salt))
  19:  md5(sha1($pass))
  20:  md5(substring(md5($pass),8,16))
  21:  md5($pass.md5(y.$salt.x).2020)
  22:  md5_custom_mss
  23:  md5_custom_nc65
  24:  md5_custom_gmshop
  25:  md5_md5_md5_bt_admin
  26:  md5($pass.$salt)_hex
  27:  md5($salt.$pass)_hex
  28:  md5($salt.$pass.$salt)_hex
  29:  md5($salt.md5($pass))_hex
  30:  md5(md5($salt).$pass)_hex
  31:  md5($pass.md5($salt))_hex
  32:  md5(md5($pass).$salt);VB;DZ_hex
  33:  md5(md5($salt).md5($pass))_hex
  34:  md5(md5($pass).md5($salt))_hex
  35:  sha1
  36:  sha1($pass.$salt)
  37:  sha1($salt.$pass)
  38:  sha1(sha1($pass))
  39:  sha1(md5($pass))
  40:  sha256
  41:  sha256($pass.$salt)
  42:  sha256($salt.$pass)
  43:  sha256(md5($pass))
  44:  sha256_shiro
  45:  sha256_custom_nccloud
  46:  sha384
  47:  sha512
  48:  sha512($pass.$salt)
  49:  sha512($salt.$pass)
  50:  sha1($pass.$salt)_hex
  51:  sha1($salt.$pass)_hex
  52:  sha256($pass.$salt)_hex
  53:  sha256($salt.$pass)_hex
  54:  sha512($pass.$salt)_hex
  55:  sha512($salt.$pass)_hex
  56:  mysql
  57:  mysql5
  58:  ntlm
  59:  MSSQL2015
  60:  bcrypt
  61:  bcrypt_md5
  62:  argon2
  63:  scrypt
  64:  phpass
```

## 3. 程序运行逻辑与解密原理

decipher 的核心原理是**彩虹版碰撞 + 实时hash计算 + 可逆算法解密**。

### 运行逻辑

1.  **缓存生成阶段 (Cache Generation)**:  
   *   用户提供明文字典（或使用内置字典）和可选的 Salt。
   *   程序遍历所有支持（或指定）的哈希算法，计算 `Hash = Algorithm(Plaintext + Salt)`。
   *   将计算结果以 `Hash:Salt:Plaintext` 的格式存储在本地缓存目录中（默认位于用户目录下的 `.decipher`）。
   *   这一步通常只需执行一次，生成的缓存越丰富，解密成功率越高。

2.  **解密匹配阶段 (Crack/Match)**:  
   *   用户输入待解密的哈希值（Target）。
   *   程序首先检查成功缓存，快速返回已破解的哈希结果。
   *   对于未破解的哈希，程序分为三个阶段进行破解：
   * *    **静态破解阶段**：对于已设置预计算功能的算法，使用预计算的哈希缓存进行快速匹配，适用于常见的哈希算法和组合。
   * *   **动态破解阶段**：对静态破解失败的哈希，使用哈希算法进行实时计算验证，无需预计算所有可能的组合。
   * *   **算法解密阶段**：对静态、动态 破解失败的哈希，使用可逆解密算法进行实时解密测试，无需预计算所有可能的组合。
   *   解密成功后，结果会被保存到成功缓存中，以便后续快速查询。

3.  **加密模式 (Encryption Mode)**:  
   *   用户可以输入明文和可选的 Salt，程序会使用指定的算法计算哈希值。
   *   支持批量加密多个明文和密钥，并可指定多种算法同时计算。

**注意**：算法分为静态算法和动态算法两种类型：
*   **预计算功能** ：预计算和算法选项目前已经解耦，目前设置为只对常用的算法进行预计算
*   **静态算法**（如MD5、SHA系列）：可以预计算缓存，解密速度快
*   **动态算法**（如bcrypt）：无法预计算，只能实时验证，只在静态算法解密失败后执行
  - 动态破解只在以下情况下执行：
    1. 预计算算法解密失败后
    2. 用户明确指定了动态算法（如bcrypt）
    3. 程序会按顺序尝试预计算算法、动态算法和加解密算法  


### 解密原理图解

```text
[待解密 Hash]
       |
       v
[检查成功缓存] --> [命中] --> [返回解密结果]
       |
       v
[静态破解阶段]
       |
       +--> [预计算缓存 (Hash:Salt:Plain)] --> [匹配] --> [成功] --> [保存到成功缓存] --> [返回解密结果]
       |
       v
[失败]
       |
       v
[动态破解阶段] (仅在静态破解失败、且存在选择动态算法时执行)
       |
       +--> [字典文件/内置字典] --> [并发验证] --> [成功] --> [保存到动态缓存] --> [返回解密结果]
       |
       v
[算法解密阶段] (仅在静态破解、动态破解、且存在选择解密算法时执行)
       |
       +--> [字典文件/内置字典] --> [并发验证] -->  [成功] --> [保存到动态缓存] --> [返回解密结果]
       |
       v
[失败] --> [无法解密]
```

## 3. 命令行参数说明

使用 `./decipher -h` 可查看帮助信息。以下是参数的中文详细介绍：

### 基础输入输出
*   `-i, --inputs`: 输入要解密的哈希值，或包含哈希值的文件路径（每行一个）。
*   `-o, --output`: 指定解密结果导出的 CSV 文件路径。

### 缓存构建与字典管理
*   `-d, --dec-dicts`: 指定自定义字典文件路径或直接输入字典字符串，用于生成明文字典的hash缓存。
*   `-s, --dec-secrets`: 指定 Salt 字符串或包含 Salt 的文件路径（默认为 "66666"），用于生成明文字典+salt字典的hash缓存。
*   `-w, --workers`: 指定生成缓存时的并发工作线程数（默认为 0，自动适配）。
*   `-R, --rec`: 清空缓存目录下的所有文件，使用后需要重新生成缓存。
*   `-D, --dec`: 对hash预计算缓存文件进行去重整理。

### 算法控制
*   `-a, --algos`: 指定使用的哈希算法关键字（例如 `md5`, `sha1`, `bcrypt`）。支持部分匹配，会自动匹配包含指定关键字的所有算法。如果不指定，默认使用所有可用算法解密。
*   `-L, --list`: 列出当前支持的所有哈希算法。


### 加密模式
*   `--et, --encrypt-text`: 输入要加密的明文，或包含明文的文件路径（每行一个）。
*   `--es, --encrypt-salt`: 输入加密时使用的 Salt，或包含 Salt 的文件路径（每行一个）。

### 其他选项
*   `--data-dir`: 指定工具的数据存储目录（默认 `~/.decipher`）。
*   `--ll`: 设置日志级别 (debug, info, warn, error)，默认 `info`。
*   `--lf`: 指定日志输出文件路径。
*   `--lcf`: 控制台日志格式，可选 T(时间)/L(级别)/C(调用处)/F(函数)/M(消息)，默认 `LM`。
*   `-v, --version`: 显示程序版本信息并退出。

## 4. 使用示例

### 1. 初始化缓存（首次使用推荐）
使用内置字典生成缓存：
```bash
./decipher -d
```

### 2. 添加自定义字典
将 `my_passwords.txt` 中的密码，并使用salt=666 来进行hash预计算并加入缓存：
```bash
./decipher -d ./my_passwords.txt -s 666
```

### 3. 单个哈希解密
```bash
./decipher -i e10adc3949ba59abbe56e057f20f883e
```

### 4. 批量解密
从 `hashes.txt` 读取哈希列表进行解密，并将结果保存到 `result.csv`：
```bash
./decipher -i ./hashes.txt -o ./result.csv
```

### 5. 指定算法解密 当前使用关键字模糊匹配
只使用 MD5 算法进行解密：
```bash
./decipher -i e10adc3949ba59abbe56e057f20f883e -a md5
```

### 6. 使用动态算法解密
使用 bcrypt 动态算法进行解密（注意：动态算法只在静态算法解密失败后执行）：
```bash
./decipher -i <bcrypt_hash> -a bcrypt -d ./custom_dict.txt
```

同时使用静态和动态算法进行解密：
```bash
./decipher -i <hash> -a md5,bcrypt -d ./custom_dict.txt
```

### 7. 加密模式
使用 MD5 算法加密明文 "123456"：
```bash
./decipher --et 123456 -a md5
```

### 8. 加密模式 使用多个算法加密明文 "password" 并添加 Salt "salt123"：
```bash
./decipher --et password --es salt123 -a md5,sha1,sha256
```

### 9. 动态破解示例
使用自定义字典和动态算法进行解密：
```bash
./decipher -i <bcrypt_hash> -a bcrypt -d ./custom_dict.txt
```

