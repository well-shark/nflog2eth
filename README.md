# nflog2eth: NFLOG帧转换为以太网帧

借鉴 [nflog_to_eth](https://github.com/jmhIcoding/nflog_to_eth) 开发，区别：
1. C++ 实现
2. 支持大包处理（小于 65536 字节）
3. 支持指定 MAC 地址

## 依赖环境

Mac:
```shell
xcode-select --install
```

Ubuntu:
```shell
sudo apt-get install libpcap-dev g++
```

> 其他操作系统未验证，可参考 [nflog_to_eth](https://github.com/jmhIcoding/nflog_to_eth)。

## 手动编译

```shell
cd nflog2eth
make
```
编译完成后，`nflog2eth`可执行程序在 `bin/` 目录下。

## 使用说明

```shell
Usage: bin/nflog2eth -r <input_file> [-w <output_file>] [-src_mac <src_mac>] [-dst_mac <dst_mac>]
```
支持四个参数：
- `-r`：指定输入文件，**必需参数**
- `-w`：指定输出文件，默认为 “输入文件名-eth.后缀”
- `-src_mac`：指定源 MAC 地址，默认为 “11:11:11:11:11:11”
- `-dst_mac`：指定目的 MAC 地址，默认为 “22:22:22:22:22:22”

示例：
```shell
nflog2eth -r test.pcap -w test-eth.pcap -src_mac 11:11:11:11:11:11 -dst_mac 22:22:22:22:22:22
```