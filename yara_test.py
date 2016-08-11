import yara
import glob

flist = glob.glob('test_dataset/*')
rules = yara.compile('learn.yar')

for fname in flist:
	data = open(fname, 'rb').read().decode()
	result = rules.match(data=data)
	if len(result) == 0:
		print(fname, "not match")
	else:
		print(fname, "match")
