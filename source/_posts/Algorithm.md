---
title: 洛谷p1216
date: 2023-04-14 14:48:40
categories:
- 算法
tags:
- 动态规划
toc: true
description: |
    杏花微雨
    已经转移阵地了
---

## 二分查找

### 旋转数组找最小值

mid和right比较

```c++
if(nums[mid]<nums[right]){
     right=mid;
}else{
     left=mid+1;
}
```

## `[USACO1.5][IOI1994]`数字三角形 Number Triangles

## 题目描述

观察下面的数字金字塔。

写一个程序来查找从最高点到底部任意处结束的路径，使路径经过数字的和最大。每一步可以走到左下方的点也可以到达右下方的点。

```cpp
        7 
      3   8 
    8   1   0 
  2   7   4   4 
4   5   2   6   5 
```

在上面的样例中,从 $7 \to 3 \to 8 \to 7 \to 5$ 的路径产生了最大

## 输入格式

第一个行一个正整数 $r$ ,表示行的数目。

后面每行为这个数字金字塔特定行包含的整数。

## 输出格式

单独的一行,包含那个可能得到的最大的和。

## 样例 #1

### 样例输入 #1

```bash
5
7
3 8
8 1 0
2 7 4 4
4 5 2 6 5
```

### 样例输出 #1

```bash
30
```

## 提示

【数据范围】  
对于 $100\%$ 的数据，$1\le r \le 1000$，所有输入在 $[0,100]$ 范围内。

题目翻译来自NOCOW。

USACO Training Section 1.5

IOI1994 Day1T1

## 动态规划

>由于从上而下不好计算，从下而上，以下一行与本行和 较大值来替代本行元素，即可从下而上完成动态规划 `dp[i-1][j]+=max(dp[i][j]+dp[i][j+1]);` 从而解决问题。

代码如下

```cpp
    #include <iostream>
    using namespace std;
    int main(){
        int arr[1000][1000];
        int n;
        cin>>n;
        for(int i=0;i<n;i++){
            for(int j=0;j<=i;j++){
                cin>>arr[i][j];
            }
        }
    
        for(int i=n-2;i>=0;i--){
            for(int j=0;j<=i;j++){
                arr[i][j]+=max(arr[i+1][j],arr[i+1][j+1]);
            }
        }
        cout<<arr[0][0];
    
    
        return 0;
}
```
