##索引和切片

z='hello'
print(z[-2])
print(z[1:4])

##字符串定义##
print('hello'+str(1)+'first')


##string不可改变，list可以,区分大小写##

s=('sasasas')
print(s[3])
L=['a','b','c','d']
L[3]='C'
print(L[1:])

test = s[:3]+'G'+s[1:]

print(test)
##替换##
a = 'hello nfline'
ar = a.replace('nfline','www')
print(ar)

##split用法用\n分隔##

c = 'sasasasasas\\nnfline\\nheelo'

d = c.split('\n')[0:]
print(d)
##分割和拼接##
print(c.split('nfline')[0])
print('wwwnf'+c.split('nfline')[1])
print('\n'.join(d))
##替换0号位##
print(c.replace(c.split('nfline')[0],''))


