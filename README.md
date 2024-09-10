# anonpage_recycle
主动回收进程匿名页的一个demo。

使用说明：

  1、驱动编译加载正常；

  2、系统支持swap交互并且交互分区已经创建好

  3、echo pid > /proc/page_test/pid 测试匿名页回收
