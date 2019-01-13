tcpForward  
======  
TCP转发工具：  
    一个高效率的多线程并发TCP转发服务器  
    强大的acl可以根据客户端的请求信息转发到不同的IP:PORT  
    同时还能使用CONNECT隧道进行代理访问  
    当然也可以限制客户端的网速和流量  
  
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