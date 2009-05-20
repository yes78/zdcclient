ZDC_Client v0.1 Readme

编译：
	编译需要libpcap库，一般Linux发行版里面安装libpcap-dev包即可，如ubuntu： sudo apt-get install libpcap-dev
	然后从命令行进入源代码目录，运行make，应该很快就能生成ZDC_Client，当然前提是系统中安装了gcc等编译环境，这里不再累赘
	
	
运行：
	运行需要root权限，看例子即可：
	
	sudo ./ZDC_Client -u username -p password -g 172.18.18.254 -d 202.192.18.1 --background
	
	u、p、g、d分别是我的用户名、密码、网关地址和DNS服务器地址，--background参数可让程序进入后台运行，具体可以运行
	./ZDC_Client --help查看
	

A PT Work. 
Blog: http://apt-blog.co.cc
GMail: pentie@gmail.com

2009-05-18
