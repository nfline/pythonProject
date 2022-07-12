print('welcome to nfline')
##插入随机模块##
import random

chioce = ['a', 'ss', 'dd', 'ff']

print(random.choice(chioce))

##测试主动换行但是输出时还是同一行##
test = 'sasasadsdadsasasasasas'\
    'asasaswqwqwq'\
    'sawwwqqqq'
print (test)

##for循环，打印结束默认换行##

asd = 'nfline'

for n in asd:
    print(n)
##if测试##
if 'e' in asd:
    print('e in asd nfline')
##for循环，打印不换行##
qaz='nflinejiayou'

for c in qaz:
    print(c,end='')
