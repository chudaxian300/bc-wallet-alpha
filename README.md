# 区块链钱包(alpha)源码

### 项目介绍

本项目为基于以太坊的简易区块链钱包, 用户可生成或导入区块链账号，查询余额，进行代币交易转账或查询交易记录，满足用户基本的区块链以太币钱包交易需求

### 项目细节

- 通过用椭圆曲线数字签名算法生成公钥和私钥，将公钥哈希用base58编码生成区块链地址，生成账户。
- 对交易进行SHA-256哈希计算，通过ecdsa.Sign对交易进行签名，以验证发送方的身份和交易数据。
- 实现工作量证明算法(POW)，通过对当前区块进行SHA-256哈希计算除以2的256次方小于难度值。
- 该项目运行方式为谷歌浏览器插件(类似metaMask)。

### 如何使用

1. 启动命令 go run .\serve && go run .\walletServer
2. 打开浏览器，进入管理拓展程序页面
3. 将bc_wallet_web拖入页面
4. 点击右上方拓展程序区并选择即可使用

### 项目截图
##### 1.账户信息页
![38d1d92b0a8fe0c64ff07ff0dfb8bd6](https://github.com/chudaxian300/bc-wallet-alpha/assets/81302819/de640030-fbd4-4b1b-b406-6fe6e924ff93)
##### 2.转账页
![64befcc90ae61b0108d166079c44597](https://github.com/chudaxian300/bc-wallet-alpha/assets/81302819/64c7e4aa-da82-4264-9c07-808fd22c9664)
##### 3.交易记录页
![98a40dbca581e2b411c85e270fd64b3](https://github.com/chudaxian300/bc-wallet-alpha/assets/81302819/f50dcec0-6c3c-41dc-b6e1-2f0562380d44)
##### 4.查找页
![3f5148983136d52e89bf38928f1b8a6](https://github.com/chudaxian300/bc-wallet-alpha/assets/81302819/ad5bcd77-f178-486e-a723-b0fc6981d22d)
