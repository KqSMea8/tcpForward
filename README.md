tcpForward  
======  
TCP转发工具：  
    一个高效率的多线程并发TCP转发服务器  
    根据客户端的IP地址以及数据内容转发到不同的IP:PORT  
    同时还能限制客户端的网速和流量  
  
##### 启动参数：  
    -c config.conf          配置文件路径  
    -v                      显示版本  
    -h                      显示帮助  
  
##### BUG：  
    待发现
  
##### 编译:  
~~~~~
Linux/Android:  
    make  
Android-ndk:  
    ndk-build  
~~~~~