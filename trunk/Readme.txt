ZDC_Client v0.3 Readme

编译：
	编译需要libpcap库，一般Linux发行版里面安装libpcap-dev包即可，如ubuntu： sudo apt-get install libpcap-dev
	然后从命令行进入源代码目录，运行make，应该很快就能生成ZDC_Client，当然前提是系统中安装了gcc等编译环境，这里不再累赘
	
运行：
	运行需要root权限，看例子即可：
	
	sudo ./zdclient -u username -p password -g 172.18.18.254 -d 202.192.18.1 --background
	
	u、p、g、d分别是用户名、密码、网关地址和DNS服务器地址，--background参数可让程序进入后台运行，具体可
	./zdclient --help查看
	
	压缩包内提供了一个启动脚本zdcrun，带检测root权限功能，用gedit等编辑软件修改其中的参数，以后运行sudo ./zdcrun即可。
	
终止：
	默认方式启动的程序，按Ctrl + C即可正常下线，程序终止；
	在以后台方式启动后，程序每隔约20秒就输出一次协议提示，其中方括号［xxx］的数值为进程pid，可用sudo kill xxx可终止进程。
	如果已经了运行时的关闭窗口，就只能使用ps aux|grep zdclient来找到pid了。

DHCP：
	请留意所在网络是否要求DHCP，如果有请加上--dhcp参数，同时完成认证后运行一次dhclient，或者

A PT Work. 

Blog: http://apt-blog.co.cc
GMail: pentie@gmail.com

2009-05-20
