cars = {'A':{'speed':70,
        'color':2},
        'B':{'speed':60,
        'color':3}}
		
		
for x in cars:
    print (x)
    for y in cars[x]:
        print (y,':',cars[x][y])