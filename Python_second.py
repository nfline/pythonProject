##字符串拼接
##通过字符串拼接的方式，打印出QYTANG'day 2014-9-28。不要忘记中间的空格。

a='QYTANG\'day'+' '+'2014-9-28'
print(a)

##通过切片创建子字符串
##现在有个字符串word = " scallywag"，创建一个变量sub_word，通过切片的方式获得字符串"ally"，将字符串的内容赋予sub_word。
word=" scallywag"
sub_word=word[3:7]
print(sub_word)

##创造自己的语言 我们将在英语的基础上创建自己的语言：在单词的最后加上-，然后将单词的第一个字母拿出来放到单词的最后，然后在单词的最后加上y
##例如，Python，就变成了ython-Py

c='Python'
d=c[1:6]
e=c[0:2]
print(d+'-'+e)