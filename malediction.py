import itertools
import sys
import random
import time
"""
TODO:
1. Write miscellaneous dictionaries to files and parse files into dictionaries on load [DONE!]
2. Sliding window average for aggregation (as memory exhausts [maxes out at window size of 16]) [DONE!]
3. Back propagation of weight correction [Kinda~]
4. Apply to TCP data section
5. Apply to UDP
6. Apply to conversation
7. Add in multithreading

Test TCP Packet
dst        : DestMACField                        = 'a0:99:9b:07:34:13' (None)
src        : SourceMACField                      = '00:0c:29:52:c6:27' (None)
type       : XShortEnumField                     = 2048            (36864)
--
version    : BitField (4 bits)                   = 4L              (4)
ihl        : BitField (4 bits)                   = 5L              (None)
tos        : XByteField                          = 0               (0)
len        : ShortField                          = 52              (None)
id         : ShortField                          = 4370            (1)
flags      : FlagsField (3 bits)                 = 2L              (0)
frag       : BitField (13 bits)                  = 0L              (0)
ttl        : ByteField                           = 64              (64)
proto      : ByteEnumField                       = 6               (0)
chksum     : XShortField                         = 19749           (None)
src        : SourceIPField (Emph)                = '10.0.100.65'   (None)
dst        : DestIPField (Emph)                  = '10.0.100.76'   (None)
options    : PacketListField                     = []              ([])
--
sport      : ShortEnumField                      = 9009            (20)
dport      : ShortEnumField                      = 60152           (80)
seq        : IntField                            = 3970448338      (0)
ack        : IntField                            = 495243903       (0)
dataofs    : BitField (4 bits)                   = 8L              (None)
reserved   : BitField (3 bits)                   = 0L              (0)
flags      : FlagsField (9 bits)                 = 16L             (2)
window     : ShortField                          = 227             (8192)
chksum     : XShortField                         = 62938           (None)
urgptr     : ShortField                          = 0               (0)
options    : TCPOptionsField                     = [('NOP', None), ('NOP', None), ('Timestamp', (4888996, 1626178029))] ({})
None

Test UDP Packet
dst       = 00:00:5e:00:01:01
src       = 6c:88:14:84:a8:c0
type      = IPv4
--
version   = 4L
ihl       = 5L
tos       = 0x0
len       = 59
id        = 25086
flags     =
frag      = 0L
ttl       = 128
proto     = udp
chksum    = 0x14f3
src       = 134.240.190.66
dst       = 134.240.247.157
options   =
--
sport     = 60706
dport     = domain
len       = 39
chksum    = 0x9d84
"""

###GLOBALS###
testLimit = 16
layeredWeightDict = {}
layeredActivationRequirementsDict = {}
layeredActivatedStatusDict = {}
probDict = {}
debugFlag = False
learnFlag = False
testFlag = False

def testDictionaryInstantiation(section,dictType):
	if(debugFlag):
		print("TEST DICTIONARY INSTANTIATION #"+str(section)+"\n")
	global layeredWeightDict
	global layeredActivationRequirementsDict
	global layeredActivatedStatusDict
	global probDict
	indexes = list(range(section,testLimit+section))
	for i in range(section,testLimit+section):
		tl = list(itertools.combinations(indexes,i))
		for j in tl:
			if(not (j in layeredWeightDict)):
				layeredWeightDict[j]=round(random.uniform(0.0,1.0),2)
	for i in range(section,testLimit+section):
		tl = list(itertools.combinations(indexes,i))
		for j in tl:
			if(not (j in layeredActivationRequirementsDict)):
				layeredActivationRequirementsDict[j]=round(random.uniform(0.0,1.0),2)
	for i in range(section,testLimit+section):
		tl = list(itertools.combinations(indexes,i))
		for j in tl:
			if(not (j in layeredActivatedStatusDict)):
				layeredActivatedStatusDict[j]=False
	#ETHERNET
	dstEF = {'a0:99:9b:07:34:13':0.9}
	srcEF = {'00:0c:29:52:c6:27':0.8}
	typeF = {'2048':0.7}
	#IP
	versionF = {'4L':0.6}
	ihlF = {'5L':0.5}
	tosF = {'0':0.4}
	lenIPF = {'52':0.3}
	idfF = {'4370':0.2}
	flagsIPF = {'2L':0.1}
	fragF = {'0L':0.9}
	ttlF = {'64':0.8}
	protoF = {'6':0.8}
	chksumIPF = {'19749':0.7}
	srcF = {'10.0.100.65':0.6}
	dstF = {'10.0.100.76':0.5}
	optionsF = {'':0.4}
	#TCP & UDP
	sportF = {'9009':0.3}
	dportF = {'60152':0.2}
	chksumF = {'62938':0.4}
	#TCP
	seqF = {'3970448338':0.1}
	ackF = {'495243903':0.9}
	dataofsF = {'8L':0.8}
	reservedF = {'0L':0.7}
	flagsF = {'16L':0.6}
	windowF = {'227':0.5}
	urgptrF = {'0':0.3}
	option1F = {'NOP':0.2}
	option2F = {'NOP':0.1}
	optionTime1F = {'4888996':0.9}
	optionTime2F = {'1626178029':0.8}
	#UDP
	lenF = {'39':0.4}
	if(dictType == 0):
		#TCP
		probDict = {'edstFE':dstEF,'srcFE':srcEF,'typeFE':typeF,'versionFIP':versionF,'ihlFIP':ihlF,'tosFIP':tosF,'lenFIP':lenIPF,'idfFIP':idfF,'fragFIP':fragF,'ttlFIP':ttlF,'protoFIP':protoF,'chksumFIP':chksumIPF,'srcFIP':srcF,'dstFIP':dstF,'optionsFIP':optionsF,'sportFB':sportF,'dportFB':dportF,'chksumFB':chksumF,'seqFT':seqF,'ackFT':ackF,'dataofsFT':dataofsF,'reservedFT':reservedF,'flagsFT':flagsF,'windowFT':windowF,'urgptrFT':urgptrF,'option1FT':option1F,'option2FT':option2F,'optionTime1FT':optionTime1F,'optionTime2FT':optionTime2F}
	else:
		if(dictType == 1):
			#UDP
			probDict = {'edstFE':dstEF,'srcFE':srcEF,'typeFE':typeF,'versionFIP':versionF,'ihlFIP':ihlF,'tosFIP':tosF,'lenFIP':lenIPF,'idfFIP':idfF,'fragFIP':fragF,'ttlFIP':ttlF,'protoFIP':protoF,'chksumFIP':chksumIPF,'srcFIP':srcF,'dstFIP':dstF,'optionsFIP':optionsF,'sportFB':sportF,'dportFB':dportF,'chksumFB':chksumF,'lenFU':lenF}

class packetNeuron:
	weight = 0
	layer = 0
	randomDeviation = 0
	probANotB = 0
	activationRequirements = []
	a = ()
	activated = False

	def __init__(self,initWeight,initLayer,initRandomDeviation,initProbANotB,initActivationRequirements,initA):
		self.weight = initWeight
		self.layer = initLayer
		self.randomDeviation = initRandomDeviation
		self.probANotB = initProbANotB
		self.activationRequirements = initActivationRequirements
		self.a = initA
		self.activated = False

	def __str__(self):
		return "["+str(self.weight)+","+str(self.layer)+","+str(self.randomDeviation)+","+str(self.probANotB)+","+str(self.activationRequirements)+", Activated Nodes: "+str(self.a)+","+str(self.activated)+"]"

	def __repr__(self):
		return "["+str(self.weight)+","+str(self.layer)+","+str(self.randomDeviation)+","+str(self.probANotB)+","+str(self.activationRequirements)+", Activated Nodes: "+str(self.a)+","+str(self.activated)+"]"

	def updateWeight(newWeight):
		weight = newWeight
		
def getFromWeightDict(layerCombo):
	return layeredWeightDict[layerCombo]

def getFromProbDict(packetObj, fieldNums,pType):
	summation = 0
	if(pType == 0):
		searchTermIndex = ['edstFE','srcFE','typeFE','versionFIP','ihlFIP','tosFIP','lenFIP','idfFIP','fragFIP','ttlFIP','protoFIP','chksumFIP','srcFIP','dstFIP','optionsFIP','sportFB','dportFB','chksumFB','seqFT','ackFT','dataofsFT','reservedFT','flagsFT','windowFT','urgptrFT','option1FT','option2FT','optionTime1FT','optionTime2FT']
	else:
		if(pType == 1):
			searchTermIndex = ['edstFE','srcFE','typeFE','versionFIP','ihlFIP','tosFIP','lenFIP','idfFIP','fragFIP','ttlFIP','protoFIP','chksumFIP','srcFIP','dstFIP','optionsFIP','sportFB','dportFB','chksumFB','lenFU']
	for i in fieldNums:
		if(packetObj[i] in probDict[searchTermIndex[i]]):
			summation += probDict[searchTermIndex[i]][packetObj[i]]
		else:
			summation += 0.25 #assumed base for anomalies
	return summation

class NeuralNetwork:
	neurons = [[]]*10 #should be a list of lists

	def __init__(self):
		print("Neural Network Created!")

	def genPNetwork(self,packetObj,windowIndex,packetType):
		#TCP Packet has 30 header fields
		#UDP Packet has 19 header fields
		locTestLimit = 16
		layerNeurons = []
		layers = []
		fieldIndexes = list(range(windowIndex,locTestLimit+windowIndex))
		for i in range(windowIndex,locTestLimit+windowIndex):
			if(debugFlag):
				print("###DEBUG###\nLayer Loop "+str(i)+"\n")
			layers.append(list(itertools.combinations(fieldIndexes,i))) #creates a list of layers with each layer containing a list of the combinations for that layer (ex. [[1,2,3],[(1,2),(1,3),(2,3)],[(1,2,3)]])
		layerNeurons = [[]] * len(layers)
		if(debugFlag):
			print(str(layerNeurons))
		for j in range(0,len(layerNeurons)):
			if(debugFlag):
				print("###DEBUG###\nNetwork Loop "+str(j)+"\n")
			for k in range(0,len(layers[j])):
				if(k < 1):
					pn = packetNeuron(getFromWeightDict(layers[j][k]),j,0,getFromProbDict(packetObj,layers[j][k],packetType),[],layers[j][k])
#					if(debugFlag):
#						print("Packet Neuron: "+str(packetNeuron))
				else:
					pn = packetNeuron(getFromWeightDict(layers[j][k]),j,0,getFromProbDict(packetObj,layers[j][k],packetType),list(itertools.combinations(layers[j][k],len(layers[j][k])-1)),layers[j][k])
#					if(debugFlag):
#						print("Packet Neuron: "+str(packetNeuron))
				layerNeurons[j].append(pn)
		self.neurons = layerNeurons
		if(debugFlag):
			print(str(layerNeurons))

	def determination(self):
		cumulativeWeight = 0
		for layerIndex in range(0,len(self.neurons)):
			for neuronIndex in range(0,len(self.neurons[layerIndex])):
				activatedReqTest = True
				for activeReq in self.neurons[layerIndex][neuronIndex].activationRequirements:
					activatedReqTest = activatedReqTest and layeredActivatedStatusDict[activeReq] #checks each activation requirement for the given neuron
				if((self.neurons[layerIndex][neuronIndex].probANotB > layeredActivationRequirementsDict[self.neurons[layerIndex][neuronIndex].a]) and activatedReqTest): #checks if the neuron activation requirements are met and the neuron satisfies the requisite probability for activation
					self.neurons[layerIndex][neuronIndex].activated = True #update neuron activation status for the neuron itself
					layeredActivatedStatusDict[self.neurons[layerIndex][neuronIndex].a] = True #update activation status dict
					cumulativeWeight += self.neurons[layerIndex][neuronIndex].probANotB * self.neurons[layerIndex][neuronIndex].weight #add weight*prob to cumulative weight
		return cumulativeWeight

	def learn(self):
		learnRate = 0.1
		malB = False
		mal = raw_input("Correct?(y/n)?: ")
		if("y" in mal):
			malB = True
		learnList = []
		for i in layeredActivatedStatusDict.keys():
			if(layeredActivatedStatusDict[i]):
				learnList.append(i)
		queue= []
		learnNeuron = max(learnList,key=len)
		for i in learnList:
			if(len(i) == len(learnNeuron)):
				queue.append((i,1))
		while(len(queue) > 0):
			qT = queue.pop()
			reqs = list(itertools.combinations(qT[0],len(qT[0])-1))
			if(malB):
				layeredWeightDict[qT[0]] = layeredWeightDict[qT[0]] + ((learnRate * pow(layeredWeightDict[qT[0]]-1,2)/1) * qT[1])
				if(debugFlag):
					print("Weight Adjustment[Up]: "+str(layeredWeightDict[qT[0]]))
				for j in reqs:
					queue.insert(0,(j,0.1*qT[1]))
			else:
				layeredWeightDict[qT[0]] = layeredWeightDict[qT[0]] - ((learnRate * pow(layeredWeightDict[qT[0]]-1,2)/1) * qT[1])
				if(debugFlag):
					print("Weight Adjustment[Down]: "+str(layeredWeightDict[qT[0]]))
				for j in reqs:
					queue.insert(0,(j,0.1*qT[1]))
					
def loadDictionaries(section,dictType):
	global layeredWeightDict
	global layeredActivationRequirementsDict
	global layeredActivatedStatusDict
	global probDict
	if(dictType == 0):
		sectionFile = "TCPsection"+str(section)+".txt"
		if(debugFlag):
			print("Reading from "+str(sectionFile)+"...")
		file = open(sectionFile,"r+")
		text = file.read()
		if(debugFlag):
			print(text)
		#need to iteratively load files
		textList = text.split("\n")
		lWDi = textList.index("---1---")+1
		lARDi = textList.index("---2---")+1
		lASDi = textList.index("---3---")+1
		pDi = textList.index("---4---")+1
		textSegment = textList[lWDi]
		newDict = {}			
		l3t = textSegment.split(", (")
		l3t[0] = l3t[0][2:]
		l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
		for i in l3t:
			keyA = i[0:i.index(')')]
			keyC = []
			for j in keyA.split(','):
				if(not (j == '')):
					keyC.append(int(j.strip()))
			keyD = tuple(keyC)
			value = float(i[i.index(": ")+2:])
			newDict[keyD] = value
		layeredWeightDict = newDict
		if(debugFlag):
			print("Layered Weight Dictionary: "+str(layeredWeightDict))
		textSegment = textList[lARDi]
		newDict = {}			
		l3t = textSegment.split(", (")
		l3t[0] = l3t[0][2:]
		l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
		for i in l3t:
			keyA = i[0:i.index(')')]
			keyC = []
			for j in keyA.split(','):
				if(not (j == '')):
					keyC.append(int(j.strip()))
			keyD = tuple(keyC)
			value = float(i[i.index(": ")+2:])
			newDict[keyD] = value
		layeredActivationRequirementsDict = newDict
		if(debugFlag):
			print("Layered Activation Requirements Dictionary: "+str(layeredActivationRequirementsDict))
		textSegment = textList[pDi]
		newDict = {}			
		l3t = textSegment.split(", ")
		l3t[0] = l3t[0][1:]
		l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
		for i in l3t:
			inter = i.split(": ")
			key = inter[0][1:-1]
			keyValue = inter[1][2:-1]
			valueValue = float(inter[2][:-1])
			interDict = {keyValue:valueValue}
			newDict[key] = interDict
		probDict = newDict
		if(debugFlag):
			print("Probability Dictionary: "+str(probDict))
		indexes = list(range(section,16+section))
		for i in range(section,16+section):
			tl = list(itertools.combinations(indexes,i))
			for j in tl:
				if(not (j in layeredActivatedStatusDict)):
					layeredActivatedStatusDict[j]=False
		if(debugFlag):
			print("Layered Activated Status Dictionary: "+str(layeredActivatedStatusDict))
	else:
		if(dictType == 1):
			sectionFile = "UDPsection"+str(section)+".txt"
			if(debugFlag):
				print("Reading from "+str(sectionFile)+"...")
			file = open(sectionFile,"r+")
			text = file.read()
			if(debugFlag):
				print(text)
			#iteratively load files
			textList = text.split("\n")
			lWDi = textList.index("---1---")+1
			lARDi = textList.index("---2---")+1
			lASDi = textList.index("---3---")+1
			pDi = textList.index("---4---")+1
			textSegment = textList[lWDi]
			newDict = {}			
			l3t = textSegment.split(", (")
			l3t[0] = l3t[0][2:]
			l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
			for i in l3t:
				keyA = i[0:i.index(')')]
				keyC = []
				for j in keyA.split(','):
					if(not (j == '')):
						keyC.append(int(j.strip()))
				keyD = tuple(keyC)
				value = float(i[i.index(": ")+2:])
				newDict[keyD] = value
			layeredWeightDict = newDict
			if(debugFlag):
				print("Layered Weight Dictionary: "+str(layeredWeightDict))
			textSegment = textList[lARDi]
			newDict = {}			
			l3t = textSegment.split(", (")
			l3t[0] = l3t[0][2:]
			l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
			for i in l3t:
				keyA = i[0:i.index(')')]
				keyC = []
				for j in keyA.split(','):
					if(not (j == '')):
						keyC.append(int(j.strip()))
				keyD = tuple(keyC)
				value = float(i[i.index(": ")+2:])
				newDict[keyD] = value
			layeredActivationRequirementsDict = newDict
			if(debugFlag):
				print("Layered Activation Requirements Dictionary: "+str(layeredActivationRequirementsDict))
			textSegment = textList[pDi]
			newDict = {}			
			l3t = textSegment.split(", ")
			l3t[0] = l3t[0][1:]
			l3t[len(l3t)-1] = l3t[len(l3t)-1][0:-1]
			for i in l3t:
				inter = i.split(": ")
				key = inter[0][1:-1]
				keyValue = inter[1][2:-1]
				valueValue = float(inter[2][:-1])
				interDict = {keyValue:valueValue}
				newDict[key] = interDict
			probDict = newDict
			if(debugFlag):
				print("Probability Dictionary: "+str(probDict))
			indexes = list(range(section,16+section))
			for i in range(section,16+section):
				tl = list(itertools.combinations(indexes,i))
				for j in tl:
					if(not (j in layeredActivatedStatusDict)):
						layeredActivatedStatusDict[j]=False
			if(debugFlag):
				print("Layered Activated Status Dictionary: "+str(layeredActivatedStatusDict))


def storeDictionaries(section,dictType):
	if(dictType == 0):
		sectionFile = "TCPsection"+str(section)+".txt"
		if(debugFlag):
			print("Writing to "+sectionFile+"...")
		file = open(sectionFile,"r+")
		if(debugFlag):
			print("Layered Weight Dictionary: "+str(layeredWeightDict))
			print("Layered Activation Requirements Dictionary: "+str(layeredActivationRequirementsDict))
			print("Layered Activated Status Dictionary: "+str(layeredActivatedStatusDict))
		text = "---1---\n"+str(layeredWeightDict)+"\n"+"---2---\n"+str(layeredActivationRequirementsDict)+"\n"+"---3---\n"+str(layeredActivatedStatusDict)+"\n"+"---4---\n"+str(probDict)+"\n"
		file.write(text)
		file.close()
	else:
		if(dictType == 1):
			sectionFile = "UDPsection"+str(section)+".txt"
			if(debugFlag):
				print("Writing to "+sectionFile+"...")
			file = open(sectionFile,"r+")
			if(debugFlag):
				print("Layered Weight Dictionary: "+str(layeredWeightDict))
				print("Layered Activation Requirements Dictionary: "+str(layeredActivationRequirementsDict))
				print("Layered Activated Status Dictionary: "+str(layeredActivatedStatusDict))
				print("Probability Dictionary: "+str(probDict))
			text = "---1---\n"+str(layeredWeightDict)+"\n"+"---2---\n"+str(layeredActivationRequirementsDict)+"\n"+"---3---\n"+str(layeredActivatedStatusDict)+"\n"+"---4---\n"+str(probDict)+"\n"
			file.write(text)
			file.close()			
		
def main(argv):
	global debugFlag
	global learnFlag
	global testFlag
	print("ARGV: "+str(argv))
	if("--help" in argv):
		print("Flags: \n     --debug        Generates debug output for all functions.\n     --learn        Enables learning mode.\n     --test         Runs with test parameters.\n     --help         Displays this help dialogue.\n")
		exit(0)
	if("--debug" in argv):
		debugFlag = True
		print("Get ready for lots of output!")
		time.sleep(2)
	if("--learn" in argv):
		learnFlag = True
	if("--test" in argv):
		testFlag = True
	"""
	#Load Packet Object File
	file = open("TCPObjects.txt","r+")
	text = file.read()
	file.close()
	textObjects = text.split("\n")
	packetList = []
	for i in textObjects:
		p = i.split(', ')
		p[0] = p[0][1:]
		p[len(p)-1] = p[len(p)-1][:-1]
		for j in range(0,len(p)):
			p[j] = p[j][1:-1]
		packetList.append(p)
	"""
	testTCPPacketObject = ['a0:99:9b:07:34:13','00:0c:29:52:c6:27','2048','4L','5L','0','52','4370','2L','0L','64','6','19749','10.0.100.65','10.0.100.76','','9009','60152','3970448338','495243903','8L','0L','16L','227','62938','0','NOP','NOP','4888996','1626178029']
	testUDPPacketObject = ['00:00:5e:00:01:01','6c:88:14:84:a8:c0','IPv4','4L','5L','0','59','25086','','0L','128','udp','0x14f3','134.240.190.66','134.240.247.157','60706','domain','39','0x9d84']
	print(str(testTCPPacketObject))
	testPN1 = NeuralNetwork()
	testPN2 = NeuralNetwork()
	if (debugFlag):
		print(str(testPN1.neurons))
		print(str(testPN2.neurons))
	windowWeights = []
	packetType = 0
	for i in range(0,14): #TCP ROUTE
		if(debugFlag):
			print("###DEBUG###\nTCP Loop "+str(i)+"\n")
		if(testFlag):
			testDictionaryInstantiation(i,0)
		else:
			loadDictionaries(i,0)
		testPN1.genPNetwork(testTCPPacketObject,i,0)
		windowWeights.append(testPN1.determination())
		print(str(windowWeights[len(windowWeights)-1]))
		learnFlag = True #temporary learning adjustment
		if(learnFlag):
			testPN1.learn()
		storeDictionaries(i,0)
	finalWeight = sum(windowWeights)/len(windowWeights)
	print("Final Weight: "+str(finalWeight))
	windowWeights = []
	for i in range(0,3): #UDP ROUTE
		if(debugFlag):
			print("###DEBUG###\nUDP Loop "+str(i)+"\n")
		if(testFlag):
			testDictionaryInstantiation(i,1)			
		else:
			loadDictionaries(i,1)
		testPN2.genPNetwork(testUDPPacketObject,i,1)
		windowWeights.append(testPN2.determination())
		print(str(windowWeights[len(windowWeights)-1]))
		learnFlag = True #temporary learning adjustment
		if(learnFlag):
			testPN2.learn()
		storeDictionaries(i,1)
	finalWeight = sum(windowWeights)/len(windowWeights)
	print("Final Weight: "+str(finalWeight))
	print("Malicious Threshold:  300")

if __name__ == "__main__":
	main(sys.argv)
