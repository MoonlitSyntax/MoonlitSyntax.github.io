---
title: javamem
date: 2023-10-04 22:06:36
categories:
- 网络安全
tags:
- web 
- java
description: |
    内存马啊内存马
---

## Tomcat

### Filter

```java
//org.apache.catalina.startup.ContextConfig#processAnnotationWebFilter是处理WebFilter的函数
//跟进发现 filterName是注解中的filterName
List<ElementValuePair> evps = ae.getElementValuePairs();
        for (ElementValuePair evp : evps) {
            String name = evp.getNameString();
            if ("filterName".equals(name)) {
                filterName = evp.getValue().stringifyValue();
                break;
            }
        }
//然后创建filterDef对象并设置filterName和filterClass(filterClass是我们创建的Filter的全限定名)
if (filterDef == null) {
            filterDef = new FilterDef();
            filterDef.setFilterName(filterName);
            filterDef.setFilterClass(className);
            isWebXMLfilterDef = false;
        } else {
            isWebXMLfilterDef = true;
        }
//之后会遍历evps:evps是   List<ElementValuePairs> evps =ae.getElementValuePairs();
//这行代码获取了一个注解（Annotation）中的所有元素-值对（Element-Value Pair）
//for 循环两次，evp.getNameString()获得的字符串结果有两个，一个是filterName，还有一个是urlPatterns，也就是我们在注解中配置那两个参数
//然后name变量被赋值为urlPatterns时得到urlPatterns并遍历，将所有的urlPattern添加进filterMap中。

for (ElementValuePair evp : evps) {
            String name = evp.getNameString();
            if ("value".equals(name) || "urlPatterns".equals(name)) {
                if (urlPatternsSet) {
                    throw new IllegalArgumentException(sm.getString(
                            "contextConfig.urlPatternValue", "WebFilter", className));
                }
                urlPatterns = processAnnotationsStringArray(evp.getValue());
                urlPatternsSet = urlPatterns.length > 0;
                for (String urlPattern : urlPatterns) {
                    // % decoded (if required) using UTF-8
                    filterMap.addURLPattern(urlPattern);
                }
            } else if ("servletNames".equals(name)) {
                String[] servletNames = processAnnotationsStringArray(evp
                        .getValue());
                servletNamesSet = servletNames.length > 0;
                for (String servletName : servletNames) {
                    filterMap.addServletName(servletName);
                }
            }

//通过调用addFilter()和addFilterMapping()将filterDef和filterMap添加进fragment中
if (!isWebXMLfilterDef) {
            fragment.addFilter(filterDef);
            if (urlPatternsSet || servletNamesSet) {
                filterMap.setFilterName(filterName);
                fragment.addFilterMapping(filterMap);
            }
        }
```
