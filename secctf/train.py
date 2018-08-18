train = "gogqrcqyvkcobnezetzhrvasef"
num = 1
add = 2
for i in range(len(train)):
	shit = ord(train[i])
	for j in range(num):
		shit -= 1
		if (shit == 96):
			shit = 122
	print str(unichr(shit))
	num += add
	num = num%26
	add += 1
