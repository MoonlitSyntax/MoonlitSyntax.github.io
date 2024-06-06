---
title: pythonlist
date: 2023-04-21 14:36:57
categories:
- python
tags:
- web
description: |
    可能用到的方法，以供查询
---
#### str

- `capitalize()` - 将字符串的第一个字符大写，其余字符小写
- `casefold()` - 返回一个区分大小写的等效字符串
- `center(width[, fillchar])` - 将字符串居中，使用指定字符填充两侧
- `count(sub[, start[, end]])` - 计算子字符串在字符串中出现的次数
- `encode(encoding='utf-8', errors='strict')` - 对字符串进行编码
- `endswith(suffix[, start[, end]])` - 检查字符串是否以给定的子字符串结尾
- `expandtabs(tabsize=8)` - 将字符串中的制表符替换为指定数量的空格
- `find(sub[, start[, end]])` - 查找子字符串在字符串中首次出现的位置，如果未找到则返回 -1
- `format(*args, **kwargs)` - 使用指定值替换字符串中的占位符
- `format_map(mapping)` - 使用字典替换字符串中的占位符
- `index(sub[, start[, end]])` - 类似于 find()，但如果未找到子字符串，会引发 ValueError
- `isalnum()` - 检查字符串是否只包含字母和数字
- `isalpha()` - 检查字符串是否只包含字母
- `isascii()` - 检查字符串是否只包含 ASCII 字符
- `isdecimal()` - 检查字符串是否只包含十进制数字
- `isdigit()` - 检查字符串是否只包含数字字符
- `isidentifier()` - 检查字符串是否是有效的 Python 标识符
- `islower()` - 检查字符串中的字母是否都是小写
- `isnumeric()` - 检查字符串是否只包含数值字符
- `isprintable()` - 检查字符串是否只包含可打印字符
- `isspace()` - 检查字符串是否只包含空白字符
- `istitle()` - 检查字符串是否为标题格式（每个单词首字母大写，其余字母小写）
- `isupper()` - 检查字符串中的字母是否都是大写
- `join(iterable)` - 使用字符串作为连接符，将可迭代对象中的元素连接成一个新字符串
- `ljust(width[, fillchar])` - 返回一个左对齐的字符串，并使用指定字符填充右侧
- `lower()` - 将字符串中的所有字符转换为小写
- `lstrip([chars])` - 移除字符串左侧的空白字符或指定字符
- `maketrans(x[, y[, z]])` - 为字符串的 translate() 方法生成一个映射表
- `partition(sep)` - 将字符串分割为一个 3 元组 (head, sep, tail)，head 是分隔符前的子串，sep 是分隔符本身，tail 是分隔符后的子串
- `replace(old, new[, count])` - 将字符串中的 `old` 替换为 `new`，可指定替换次数
- `rfind(sub[, start[, end]])` - 查找子字符串在字符串中最后一次出现的位置，如果未找到则返回 -1
- `rindex(sub[, start[, end]])` - 类似于 rfind()，但如果未找到子字符串，会引发 ValueError
- `rjust(width[, fillchar])` - 返回一个右对齐的字符串，并使用指定字符填充左侧
- `rpartition(sep)` - 从右侧开始将字符串分割为一个 3 元组 (head, sep, tail)
- `rsplit(sep=None, maxsplit=-1)` - 从右侧开始使用指定分隔符将字符串拆分为子字符串列表，可指定最大拆分次数
- `rstrip([chars])` - 移除字符串右侧的空白字符或指定字符
- `split(sep=None, maxsplit=-1)` - 使用指定分隔符将字符串拆分为子字符串列表，可指定最大拆分次数
- `splitlines([keepends])` - 将字符串按行拆分为一个列表，可选择是否保留换行符
- `startswith(prefix[, start[, end]])` - 检查字符串是否以给定的子字符串开头
- `strip([chars])` - 移除字符串两端的空白字符或指定字符
- `swapcase()` - 将字符串中的大小写字母互换
- `title()` - 将字符串中的每个单词的首字母大写，其余字母小写
- `translate(table)` - 使用指定的映射表替换字符串中的字符
- `upper()` - 将字符串中的所有字符转换为大写
- `zfill(width)` - 用零填充字符串的左侧，使其达到指定宽度

#### 元组

- `count(value)` - 计算指定值在元组中出现的次数
- `index(value[, start[, end]])` - 返回指定值在元组中首次出现的索引，可以指定查找范围，如果未找到则抛出 ValueError

#### 列表

- `append(item)` - 在列表末尾添加一个元素
- `extend(iterable)` - 将一个可迭代对象的元素添加到列表末尾
- `insert(index, item)` - 在指定索引处插入一个元素
- `remove(value)` - 移除列表中首次出现的指定值，如果未找到则抛出 ValueError
- `pop([index])` - 移除并返回指定索引处的元素，默认移除并返回列表最后一个元素
- `clear()` - 移除列表中的所有元素
- `index(value[, start[, end]])` - 返回指定值在列表中首次出现的索引，可以指定查找范围，如果未找到则抛出 ValueError
- `count(value)` - 计算指定值在列表中出现的次数
- `sort(key=None, reverse=False)` - 对列表元素进行排序，可指定排序键和排序顺序
- `reverse()` - 反转列表中的元素顺序
- `copy()` - 返回列表的一个浅拷贝

#### 字典

- `clear()` - 移除字典中的所有元素
- `copy()` - 返回字典的一个浅拷贝
- `get(key[, default])` - 返回字典中指定键的值，如果键不存在，则返回默认值（默认为 None）
- `items()` - 返回一个包含字典所有键值对的视图对象
- `keys()` - 返回一个包含字典所有键的视图对象
- `values()` - 返回一个包含字典所有值的视图对象
- `pop(key[, default])` - 移除并返回字典中指定键的值，如果键不存在，返回默认值（若未提供默认值，抛出 KeyError）
- `popitem()` - 移除并返回字典中的一个键值对（从 Python 3.7 开始，为最后一个键值对），如果字典为空，抛出 KeyError
- `setdefault(key[, default])` - 如果键不存在于字典中，则添加键并设置其值为默认值（默认为 None），返回该键对应的值
- `update([other])` - 将一个字典（或其他可迭代映射类型）的键值对添加到当前字典中，若有重复的键，则覆盖原有键值对
