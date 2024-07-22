	# Ubuntu 基线指导手册

# 1.   身份鉴别策略组检测

准备：

安装一个 PAM 模块来启用 cracklib 支持，这可以提供额外的密码检查功能。

在 Debian,Ubuntu 或者 Linux Mint 使用命令:

**sudo apt-get install libpam-cracklib**

这个模块在 CentOS,Fedora 或者 RHEL 默认安装了。但是在 Ubuntu 这些系统上就必需安装。

## 1.1.  口令周期检测

### 1.1.1.     最长使用周期小于等于 90 天（非强制）

**sudo vim /etc/login.defs**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181501059-358315675.png)

PASS_MAX_DAYS 90

PASS_MAX_DAYS 99999 代表永不过期

### 1.1.2.     查看密码期限：最短更换周期大于等于 2 天

PASS_MIN_DAYS 2

检查命令：

**chage -l root**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181518055-1064672146.png)

### 1.1.3.     距失效提示天数大于等于 5 天

PASS_WARN_AGE 5

## 1.2.  密码复杂度检测

### 1.2.1.     密码复杂性要求

pam_cracklib.so 支持的部分选项如下：

**retry=N\*\***：\*\*定义登录/修改密码失败时，可以重试的次数

**minlen=N\*\***：\*\*新密码的最小长度

**dcredit=N\*\***：\*\*当 N>0 时表示新密码中数字出现的最多次数；当 N<0 时表示新密码中数字出现最少次数；

**ucredit=N:**  当 N>0 时表示新密码中大写字母出现的最多次数；当 N<0 时表示新密码中大写字母出现最少次数；

**lcredit=N:**  当 N>0 时表示新密码中小写字母出现的最多次数；当 N<0 时表示新密码中小写字母出现最少次数；

**ocredit=N\*\***：\*\*当 N>0 时表示新密码中特殊字符出现的最多次数；当 N<0 时表示新密码中特殊字符出现最少次数；

**maxrepeat=N\*\***：\*\*拒绝包含多于 N 个相同连续字符的密码。 默认值为 0 表示禁用此检查

**maxsequence=N\*\***：\*\*拒绝包含长于 N 的单调字符序列的密码。默认值为 0 表示禁用此检查。实例是'12345'或'fedcb'。除非序列只是密码的一小部分，否则大多数此类密码都不会通过简单检查。

**enforce_for_root:**  如果用户更改密码是 root，则模块将在失败检查时返回错误。默认情况下，此选项处于关闭状态，只打印有关失败检查的消息，但 root 仍可以更改密码。不要求 root 用户输入旧密码，因此不会执行比较旧密码和新密码的检查

方法：

**vim** **/etc/pam.d/common-password**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181547252-497974434.png)

**password requisite pam_cracklib.so retry=3 minlen=10 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1**

在 pam_cracklib.so  后添加**minlen=10 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1**

参数含义：密码长度最小为 10 位，数字出现的最少次数为 1 次，大写字母出现最少 1 次，小写字母出现最少 1 次，特殊字符出现最少 1 次

## 1.3.  登录锁定检测

### 1.3.1.     普通用户触发锁定次数小于等于 5

### 1.3.2.     普通用户锁定时间大于等于 5 分钟

### 1.3.3.     Root 用户触发锁定次数小于等于 5

### 1.3.4.     Root 用户锁定时间大于等于 5 分钟具体安装配置：

1、修改如下配置文件：（不建议修改）

这个只是限制了用户从 tty 登录，而没有限制远程登录，如果想限制远程登录，需要改 sshd 文件

**vim /etc/pam.d/login**

在第二行添加

**auth required pam_tally2.so deny=5 unlock_time=300 even_deny_root=5 root_unlock_time=300**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181612573-655450421.png)

此处使用的是 pam_tally2 模块，如果不支持 pam_tally2 可以使用 pam_tally 模块。另外，不同的 pam 版本，设置可能有所不同，具体使用方法，可以参照相关模块的使用规则。

**注意**

**在第二行，添加内容，一定要写在前面**，如果写在后面，虽然用户被锁定，但是只要用户输入正确的密码，还是可以登录的！

这个只是限制了用户从 tty 登录，而没有限制远程登录，如果想限制远程登录，需要改 sshd 文件

2、修改 sshd 文件（建议修改）

**vim /etc/pam.d/sshd**

继续在第二行上添加

**auth required pam_tally2.so deny=5 unlock_time=300 even_deny_root=5 root_unlock_time=300**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181630047-984023369.png)

**查看用户登录失败的次数\*\***:\*\*

**sudo pam_tally2 --user**

结果

ubuntu@VM-0-5-ubuntu:~$ sudo pam_tally2 --user

Login   Failures Latest failure  From

root    3 09/29/19 15:53:24 45.119.212.105

ubuntu    9 09/29/19 15:46:58 223.107.140.84

解锁指定用户:

**sudo pam_tally2 -r -u admin**

admin@VM-0-5-ubuntu:~$ sudo pam_tally2 -r -u admin

Login   Failures Latest failure  From

admin    15 09/29/19 15:58:49 223.107.140.84

ps：这个远程 ssh 的时候，输入密码错误超过三次但是没有提示，但是**只要超过设定的值，输入正确的密码也是登陆不了的**！，还是要等到设定的时间在重新尝试输入正确密码进行登录认证

## 1.4.  Root 权限用户

### 1.4.1.     root 权限用户检测  （非强制）

检查配置文件**cat /etc/passwd**，不能包含用户标识号为 0，除 root 用户外。

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181701804-434795546.png)

以第一行为例，从左至右，分别表示：  
帐号名:口令:用户标识号:组标识号:注释性描述:主目录:登录 shell

## 1.5.  Wheel 组（非强制）

### 1.5.1.     wheel 组检测  （非强制）

命令：**cat /etc/group**

**检查文件\*\***/etc/group\***\*中，\*\***wheel\***\*后面是否有用户名，如果有，将其删除。**

如下图中示例，viewer 用户加入了 wheel 组中，因此 viewer 用户拥有了 root 的部分功能和权限，因此需要将 viewer 删除。

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181718555-108599370.png)

Wheel 组概念

Wheel 组是 Unix 系统一个遗留物。当服务器需要做比日常例行维护更高级的工作的时候，就经常需要用到 root 权限了。而这个 wheel 组就是建立用来归纳一些特殊的系统用户用的，这其中的用户都或多或少地拥有 root 的部分功能和权限。也就是说如果你不是 wheel 组成员，那就没有 root 身上任何的特权。也因为这样，使用 wheel 组成员用户的话，会尽量减少对系统“摧毁性”破坏的概率和风险。如今大多数的 Linux 发行版本中，仍然保留了 wheel 这个组，虽然它已经不像当初设计出来的那样必要了，但是有些老玩家还是忠于这种旧式经典风格的，所以他们经常还是依旧让 wheel 组发挥着以往的作用。他们是这样做的：在建立他们自己的用户时，将其添加入 wheel 组中（用 wheel 组作为用户的主组），或者使用 vigr 来编辑/etc/group 文件，将他们的用户名追加到 wheel 组那行的末尾。

## 1.6.  相同 ID 用户

### 1.6.1.     相同 ID 用户检测

命令：**cat /etc/passwd**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181735287-152552718.png)

检查配置/etc/passwd 中，是否包含用户标识号相同的帐号，用户标识号位置如下：

以第一行为例，从左至右，依次为：

帐号名:口令:用户标识号:组标识号:注释性描述:主目录:登录 shell

# 2.   访问控制策略组检测

## 2.1.  空口令监测

### 2.1.1.     空口令账户

命令：**cat /etc/shadow\*\***（检查\***\*shadow\*\***文件中密码为空且的用户）\*\*

**![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181746917-1212125126.png)**

如图上所示，输出 test3 为空口令账户，且可以登录的用户。

用户 test2:!!:18820:0:99999:7:::第二个字段是“:!!:”代表没有设置密码，但无法登录。

用户 test3::18820:0:99999:7:::第二个字段是“::”代表第二个字段密码为空，且可以登录。

如果检测出有空口令账户，可以做以下处理：

**A.** **删除该用户**

命令如下：

**userdel** **用户名**

rm -rf /home/用户名 （可选，表示删除该用户的主目录）

**B.** **给该用户设置密码**

**passwd** **用户名**

## 2.2.  弱口令检测

### 2.2.1.     弱口令账户

如果检测出弱口令账户，建议设置符合秘密复杂度要求的密码，命令如下：

**passwd** **用户名**

# 3.   安全审计策略组检测

## 3.1.  日志守护进程

### 3.1.1.     开启日志守护进程

当 rsyslog 没有在运行，则检测失败，操作命令如下：

**systemctl status rsyslog** **（查看状态）**

**systemctl stop rsyslog** **（停止）**

**systemctl start rsyslog** **（启动）**

启动成功后状态：

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181759317-955985242.png)

查看进程有没有启动：

命令：**ps -ef | grep rsyslog**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181811323-1876137368.png)

# 4.   SSH 策略检测

## 4.1.  SSH 检测

执行如下命令，修改配置文件

**sudo vim /etc/ssh/sshd_config**

## 4.1.1.     最大失败尝试登录次数小于等于 5（需要修改）

**MaxAuthTries 5**

**![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181825508-1101393820.png)**

### 4.1.2.     开启密码认证

**PasswordAuthentication yes**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181836171-1811578403.png)

### 4.1.3.     开启 RSA 认证

**RSAAuthentication yes**  （有的系统 需要手动添加）

### 4.1.4.     开启公钥验证

**PubkeyAuthentication yes**

重启 sshd 生效，重启命令如下：

CentOS 系列： **systemctl restart sshd**

后续随着建立应用账户会回收 root 权限登陆。

# 5.   入侵防范策略组监测

## 5.1.  防火墙

查看状态

**systemctl status firewalld.service**

启动防火墙

**systemctl start firewalld.service**

关闭防火墙

**systemctl stop firewalld.service**

重新启动防火墙

**systemctl restart firewalld.service**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181911341-1302733075.png)

## 5.2.  防暴力破解

安装 EDR

# 6.   恶意代码防范监测

## 6.1.   安装 EDR

# 7.   NTP 时间同步配置

安装 ntpdateNTP 时间同步配置

**apt-get install ntpdate**

编辑/etc/ntp.conf 文件

**vim /etc/ntp.conf**

添加配置

**server 10.14.1.11 prefer iburst**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181342958-1396431206.png)

其中的 prefer 优先级最高，不然在多个同步服务时，可能自己本地的 ntp 服务不被选中，会使用其他的源作为同步的时间选项。

其中的 iburst 是初始化时，每 2 秒发送一批同步

重新启动 NTP 服务器：

**service ntp restart**

查看同步情况：

**watch ntpq –p**

![](https://img2022.cnblogs.com/blog/2605882/202203/2605882-20220304181354751-1267332557.png)

1.基线 即安全基线配置，诸如操作系统、[中间件](https://cloud.tencent.com/product/tdmq?from_column=20065&from=20065)和[数据库](https://cloud.tencent.com/solution/database?from_column=20065&from=20065)的一个整体配置，这个版本中各项配置都符合安全方面的标准。比如在系统安装后需要按安全基线标准，将新机器中各项配置调整到一个安全、高效、合理的数值。

2.基线扫描 使用自动化工具、抓取系统和服务的配置项。将抓取到的实际值和标准值进行对比，将不符合的项显示出来，最终以报告 的形式体现出扫描结果有的工具将配置采集和配置对比分开，通过自动化脚本采集配置后再通过特别的软件转换为适合人类阅读的文档

3.基线加固自动化脚本的编写 本篇文章主要是记录和学习安全加固脚本，首先放几张安全加固 shell 脚本的命令语法：

![](https://ask.qcloudimg.com/http-save/yehe-2947494/010db2a0a0bf5f2c256e8a3dae1b584b.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/a8e3ed4e366e9636d928a26546a6d0ac.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/c85957d16e18c69f2197eb9da2ba525a.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/ecdb1c7e1748be34009bef38c0fe108c.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/4adba481ec1e20a9918c8ab917dbd7b4.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/c41abbb4a86e2bc965bad9ec880e66be.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/ae6ee0255bea14ce211554c53c496c73.png)

![](https://ask.qcloudimg.com/http-save/yehe-2947494/af764641566bb566590ef36c7f2ce77b.png)

基本命令语法介绍完了，借用网上的脚本来学习：

在执行脚本前需要提前做好备份：

```javascript
#!/bin/bash
cp /etc/login.defs /etc/login.defs.bak
cp /etc/security/limits.conf /etc/security/limits.conf.bak
cp /etc/pam.d/su  /etc/pam.d/su.bak
cp /etc/profile /etc/profile.bak
cp /etc/issue.net /etc/issue.net.bak
cp /etc/shadow /etc/shadow.bak
cp /etc/passwd /etc/passwd.bak
cp /etc/pam.d/passwd  /etc/pam.d/passwd.bak
cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
cp /etc/host.conf /etc/host.conf.bak
cp /etc/hosts.allow /etc/hosts.allow.bak
cp /etc/ntp.conf /etc/ntp.conf.bak
cp -p /etc/sysctl.conf /etc/sysctl.conf.bak
echo "============备份完成=================="
```

1. 检查是否设置口令更改最小间隔天数

![](https://ask.qcloudimg.com/http-save/yehe-2947494/5a39f3c404022386485af122f4147ba6.png)

```javascript
MINDAY=`cat -n /etc/login.defs | grep -v ".*#.*"| grep PASS_MIN_DAYS|awk '{print $1}'`
sed -i ''$MINDAY's/.*PASS_MIN_DAYS.*/PASS_MIN_DAYS 6/' /etc/login.defs
echo "检查口令更改最小间隔天数完成"
```

2.检查是否设置口令过期前警告天数

![](https://ask.qcloudimg.com/http-save/yehe-2947494/1df2235b33f18bf694fabe3ce92940d7.png)

```javascript
WARNAGE=`cat -n /etc/login.defs | grep -v ".*#.*"| grep PASS_WARN_AGE|awk '{print $1}'`
sed -i ''$WARNAGE's/.*PASS_WARN.*/PASS_WARN_AGE 30/' /etc/login.defs
echo "检查口令过期前警告天数完成"
```

3.检查口令生存周期

![](https://ask.qcloudimg.com/http-save/yehe-2947494/982ed110f38278a3b62d66f69388344a.png)

```javascript
MAXDAY=`cat -n /etc/login.defs | grep -v ".*#.*"| grep PASS_MAX_DAYS|awk '{print $1}'`
sed -i ''$MAXDAY's/.*PASS_MAX.*/PASS_MAX_DAYS 90/' /etc/login.defs
echo "检查口令生存周期完成"
```

4.检查口令最小长度

![](https://ask.qcloudimg.com/http-save/yehe-2947494/1a77b2e8a751e4aacd8f19caa2218f7c.png)

```javascript
MINLEN=`cat -n /etc/login.defs | grep -v ".*#.*"| grep PASS_MIN_LEN|awk '{print $1}'`
sed -i ''$MINDAY's/.*PASS_MIN_LEN.*/PASS_MIN_ LEN 6/' /etc/login.defs
echo "检查口令最小长度"
```

5.检查是否设置 grub，lilo 密码

![](https://ask.qcloudimg.com/http-save/yehe-2947494/8100006c24e8a3e555118956b0d519ad.png)

```javascript
grub="/etc/menu.lst"
if [ ! -x "$grub" ];then
touch "$grub"
echo password=123456 >> "$grub"
else
echo password=123456 >> "$grub"
fi
lilo="/etc/lilo.conf"
if [ ! -x "$lilo" ];then
touch "$lilo"
echo password=123456 >> "$lilo"
else
echo password=123456 >> "$lilo"
fi
```

6.检查是否设置 core

![](https://ask.qcloudimg.com/http-save/yehe-2947494/8497d913f604b4743671b61a4c6c528e.png)

```javascript
c=`cat -n /etc/security/limits.conf | grep "#root" | awk '{print $1}'`
d=`cat -n /etc/security/limits.conf | grep "#root" | awk '{print $5}'`
sed -i ''$c' s/$d/0/g' /etc/security/limits.conf
echo "设置* hard core 0完成"
e=`cat -n /etc/security/limits.conf | grep soft | grep core | awk '{print $1}'`
f=`cat -n /etc/security/limits.conf | grep soft | grep core | awk '{print $5}'`
sed -i ''$e' s/'$f'/0/g' /etc/security/limits.conf
echo "设置* soft core 0完成"
```

7.检查系统是否禁用 ctrl+alt+del 组合

![](https://ask.qcloudimg.com/http-save/yehe-2947494/2f85e3303e75e6e556e12fbed0ed03f9.png)

```javascript
a=`cat -n /etc/control-alt-delete.conf|grep -v "#" | grep /sbin/shutdown | awk '{print $1}'`
if [ -z $a ];then
   echo ok
else
   sed -i ''$a' s/^/#/' /etc/control-alt-delete.conf
fi
```

8.检查保留历史记录文件的大小与数量

![](https://ask.qcloudimg.com/http-save/yehe-2947494/9ad5ca992d62a2e688f590518f718fcc.png)

```javascript
echo "HISTFILESIZE=5" >> /etc/profile
echo "  检查保留历史命令的记录文件大小完成"
echo "HISTSIZE=5" >> /etc/profile
echo "检查保留历史命令的条数完成"
```

9.检查是否使用 PAM 认证模块禁止 wheel 组之外的用户 su 为 root

![](https://ask.qcloudimg.com/http-save/yehe-2947494/4e842bccc8a6055885f2b25c3d879769.png)

10.检查是否删除了/etc/issue.net 文件

![](https://ask.qcloudimg.com/http-save/yehe-2947494/f966cb5045298f2b695035f47b7be42b.png)

```javascript
if [ -f /etc/issue.net ]
then
mv /etc/issue.net /etc/issue.net.bak
else
echo "issue.net 文件不存在"
fi
if [ -f /etc/issue ]
then
mv /etc/issue /etc/issue.bak
else
echo "issue 文件不存在"
fi
```

11.是否删除与设备运行，维护等工作无关的账户

![](https://ask.qcloudimg.com/http-save/yehe-2947494/a1a8ec0dcf512d34d4c2a126f6925c45.png)

12.检查密码重复使用次数限制

![](https://ask.qcloudimg.com/http-save/yehe-2947494/7a94fe238cfb70359102ddd0e9b2f2eb.png)

13.检查是否配置账户认证失败次数限制

![](https://ask.qcloudimg.com/http-save/yehe-2947494/a10d597ac99483112839bd8dd0454cd1.png)

```javascript
cd /etc/pam.d
if [ -f system-auth ];then
cp /etc/pam.d/system-auth  /etc
#num=`grep -n "md5" /etc/system-auth | cut -d ":" -f 1`
#sed -i ''$num'    r s/$/ remember=5' /etc/system-auth
kk=`cat -n /etc/system-auth | grep -v ".*#.*"| grep md5|awk '{print $1}'`
echo $kk
version="password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=500"
sed -i ""$kk"c $version" /etc/system-auth
letter=`cat -n /etc/system-auth |grep password | grep requisite | awk '{print $1}'`
sed -i ''$letter's/pam_cracklib.so/& ucredit=-1 lcredit=-1 dcredit=-1 /' /etc/pam.d/system-auth
fi
```

14.检查是否配置关闭 IP 伪装与绑定

![](https://ask.qcloudimg.com/http-save/yehe-2947494/21c0681b0f6ca00a93b5c558f0079022.png)

```javascript
snu=`cat /etc/host.conf | awk '{print $2}'`
if [ "$snu" = "on" ]; then
echo "没有关闭ip伪装"
fi
sed -i 's/on/off/g' /etc/host.conf
echo "  关闭IP伪装完成"
```

15.检查/etc/hosts 配置

![](https://ask.qcloudimg.com/http-save/yehe-2947494/c3ea64b5775ba54375c7395c49fae78e.png)

```javascript
if [ -f hosts.allow ];then
cp /etc/hosts.allow /etc/
echo "all:172.18.12.:all" >> /etc/hosts.allow
echo "sshd:172.18.12.:all" >> /etc/hosts.allow
fi
cd /etc
if [ -f hosts.deny ];then
cp /etc/hosts.deny /etc/
echo "all:all" >> /etc/hosts.deny
fi
```

16.检查相关服务状态

![](https://ask.qcloudimg.com/http-save/yehe-2947494/94c2218fb1f3fec46933067174adb078.png)

17.检查重要文件是否存在 suid 和 sgid 权限

![](https://ask.qcloudimg.com/http-save/yehe-2947494/ddd078931f7a41e61bdcf36a082834be.png)

```javascript
find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null >file.txt
if [ -s file.txt ]; then
echo " find。。这条命令有输出"
for i in `cat file.txt`
do
chmod 755 $idoneelse
echo "find 。。这条命令没有输出"
fi
```

18.其他

![](https://ask.qcloudimg.com/http-save/yehe-2947494/ed3e50ad14919becfd431c50d47f83f3.png)

19.权限设置

```javascript
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 400 /etc/shadow
#chmod 600 /etc/xinetd.conf
chmod 644 /etc/services
chmod 600 /etc/security
chmod 600 /etc/grub.conf
chmod 600 /boot/grub/grub.conf
chmod 600 /etc/lilo.conf
echo "文件权限设置完成"
```

注：要使用下面示例代码中的命令来实施 Ubuntu 20.04 LTS 服务器的安全加固步骤，首先确保您的服务器上已安装 Git。

## 1. 更新系统

安全性始于系统的更新。确保您的 Ubuntu 服务器上的所有软件包和操作系统都是最新的版本。使用以下命令更新系统：

sudo apt update  
sudo apt upgrade

## 2. 配置防火墙

Ubuntu 默认启用了 UFW（Uncomplicated Firewall），可以轻松配置防火墙规则。首先，允许 SSH 访问，然后只允许必要的端口通过防火墙。例如，如果您运行 Web 服务器（如 Nginx 或 Apache），可以使用以下命令允许 HTTP（端口 80）和 HTTPS（端口 443）流量：

sudo ufw allow OpenSSH  
sudo ufw allow 80/tcp  
sudo ufw allow 443/tcp  
sudo ufw enable

确保在设置完防火墙规则后启用 UFW。

## 3. 禁用不必要的服务

默认情况下，Ubuntu 服务器可能启用了一些不必要的服务。检查并禁用不需要的服务以减少潜在的攻击面。使用`systemctl`命令来管理服务，例如：

# 禁用一个服务

sudo systemctl disable (service-name)

# 停止并禁用一个服务

sudo systemctl stop (service-name)  
sudo systemctl disable (service-name)

## 4. 配置 SSH 安全

SSH 是远程管理 Ubuntu 服务器的主要方式，因此确保 SSH 安全非常重要。

### 4.1 更改 SSH 默认端口

将 SSH 端口更改为非默认端口（默认是 22）可以降低恶意攻击的风险。编辑 SSH 配置文件：

sudo nano /etc/ssh/sshd_config

找到`Port`行并更改端口号，然后重新启动 SSH 服务：

sudo systemctl restart ssh

### 4.2 禁用密码登录

使用 SSH 密钥认证来替代密码登录，以提高安全性。编辑 SSH 配置文件：

sudo nano /etc/ssh/sshd_config

找到`PasswordAuthentication`行，将其设置为`no`，然后重新启动 SSH 服务：

PasswordAuthentication no

### 4.3 使用 SSH 密钥

创建 SSH 密钥对并将公钥复制到服务器上。使用以下命令来生成 SSH 密钥：

ssh-keygen -t rsa -b 4096

然后将`~/.ssh/id_rsa.pub`中的公钥复制到服务器的`~/.ssh/authorized_keys`文件中。

## 5. 防止暴力攻击

保护服务器免受暴力攻击是非常重要的。使用工具如`Fail2Ban`来防止暴力 SSH 登录尝试。首先安装`Fail2Ban`：

sudo apt install fail2ban

然后配置它来监控 SSH 登录尝试并封锁 IP 地址：

sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local  
sudo nano /etc/fail2ban/jail.local

在`jail.local`文件中，配置 SSH 规则，例如：

[sshd]  
enabled = true  
port = ssh  
filter = sshd  
logpath = /var/log/auth.log  
maxretry = 3

最后，重新启动`Fail2Ban`：

sudo systemctl restart fail2ban

## 6. 文件系统安全

### 6.1 使用 AppArmor 或 SELinux

AppArmor 和 SELinux 是 Linux 上的强制访问控制工具，可以帮助限制应用程序的权限。根据您的需求选择其中一个并配置它。

#### 配置 AppArmor

# 安装 AppArmor（如果未安装）

sudo apt install apparmor apparmor-utils

# 启用 AppArmor

sudo systemctl enable apparmor  
sudo systemctl start apparmor

然后，为您的应用程序创建或配置 AppArmor 策略文件。

#### 配置 SELinux

# 安装 SELinux（如果未安装）

sudo apt install selinux-utils selinux-basics selinux-policy-default

# 启用 SELinux

sudo selinux-activate

# 重启服务器

sudo reboot

然后，为您的应用程序创建或配置 SELinux 策略。

### 6.2 限制目录和文件权限

使用`chmod`和`chown`命令来限制对文件和目录的访问权限，确保只有授权的用户可以访问重要的系统文件。

# 修改文件或目录的权限

sudo chmod permissions /path/to/file_or_directory

# 修改文件或目录的所有者和群组

sudo chown owner:group /path/to/file_or_directory

请注意，`permissions`，`owner`和`group`应根据您的需求进行替换。

## 7. 监控和日志

监控服务器的活动并查看系统日志以及网络流量是检测潜在问题的关键。使用工具如`fail2ban`、`logwatch`和`rkhunter`来监控服务器的安全性。

## 8. 定期备份

定期备份服务器上的数据，以防止数据丢失。使用备份工具或云存储服务来创建备份策略。

## 9. 教育用户

对服务器用户进行安全意识培训，教育他们如何创建强密码、避免社会工程攻击和识别潜在的安全威胁。

## 10. 定期审计

定期审计服务器的安全性，识别并修复潜在的漏洞和问题。确保您的安全策略持续有效。
