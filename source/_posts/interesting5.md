---
title: interesting5
date: 2023-08-07 15:47:16
categories:
- 网络安全
tags:
- web 
description: |
    java
---

## JAVA

`cd /Users/dionysus/CTF/jd-gui-osx-1.6.6/JD-GUI.app/Contents/Resources/Java`
`java -jar jd-gui-1.6.6-min.jar /Users/dionysus/Downloads/ezjava.jar`

其实直接`unzip`然后idea打开就可以

jar包和war包都可以看成压缩文件，都可以用解压软件打开，jar包和war包都是为了项目的部署和发布，通常在打包部署的时候，会在里面加上部署的相关信息。这个打包实际上就是把代码和依赖的东西压缩在一起，变成后缀名为.jar和.war的文件，就是我们说的jar包和war包。但是这个“压缩包”可以被编译器直接使用，把war包放在tomcat目录的webapp下，tomcat服务器在启动的时候可以直接使用这个war包。通常tomcat的做法是解压，编译里面的代码，所以当文件很多的时候，tomcat的启动会很慢。
jar包和war包的区别：jar包是java打的包，war包可以理解为javaweb打的包，这样会比较好记。jar包中只是用java来写的项目打包来的，里面只有编译后的class和一些部署文件。而war包里面的东西就全了，包括写的代码编译成的class文件，依赖的包，配置文件，所有的网站页面，包括html，jsp等等。一个war包可以理解为是一个web项目，里面是项目的所有东西。
