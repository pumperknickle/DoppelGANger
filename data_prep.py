from gan.output import Output, OutputType, Normalization
from pcaputilities import convertToFeatures, convert_to_durations
import sys
import glob
import numpy as np
import pickle


def normalize_packet_sizes(sequence):
    normalized_packets = []
    num_seqs = []
    max_packet_size = 0
    for sequence in sequence:
        num_seq = [int(x) for x in sequence]
        max_packet_size = max(max([abs(x) for x in num_seq]), max_packet_size)
        num_seqs.append(num_seq)
    for num_seq in num_seqs:
        normalized = [(x + max_packet_size) for x in num_seq]
        normalized_packets.append(normalized)
    return normalized_packets, (max_packet_size * 2) + 1


def normalize_durations(sequences):
    max_d = 0.0
    num_seqs = []
    final_num_seqs = []
    for sequence in sequences:
        num_seq = [float(x) for x in sequence]
        max_d = max(max(num_seq), max_d)
        num_seqs.append(num_seq)
    for num_seq in num_seqs:
        final_num_seq = [x/max_d for x in num_seq]
        final_num_seqs.append(final_num_seq)
    return final_num_seqs, max_d


def find_max_len(sequences):
    max_len = 0
    for sequence in sequences:
        max_len = max(len(sequence), max_len)
    return max_len


currentLabel = 0
max_duration = 0
packet_sizes = []
durations = []
labels = []

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

# convert pcaps to packet size sequences
for path in paths:
    pcapPath = path + '/*.pcap'
    pcapFiles = glob.glob(pcapPath)
    for file in pcapFiles:
        featureV = convertToFeatures(file)
        durationV = convert_to_durations(file)
        if len(featureV) != 0:
            packet_sizes.append(featureV)
            durations.append(durationV)
            labels.append(currentLabel)
    currentLabel += 1

D = currentLabel  # number of devices

#  V is vocab size
normalized_p, V = normalize_packet_sizes(packet_sizes)
normalized_d, max_duration = normalize_durations(durations)
max_len = find_max_len(packet_sizes)

data_feature_output = [
    Output(type_=OutputType.DISCRETE, dim=V, normalization=None, is_gen_flag=False),
    Output(type_=OutputType.CONTINUOUS, dim=1, normalization=Normalization.ZERO_ONE, is_gen_flag=False)
]

data_attribute_output = [
   Output(type_=OutputType.DISCRETE, dim=D, normalization=None, is_gen_flag=False)
]


data_feature = []
data_attribute = []
data_gen_flag = []


for i in range(len(normalized_p)):
    normalized_packet = normalized_p[i]
    normalized_duration = normalized_d[i]
    label = labels[i]
    data_gen = []
    data_feat = []
    data_attr = [0] * D
    data_attr[label] = 1.0
    for j in range(max_len):
        if len(normalized_packet) <= j:
            data_gen.append(0.0)
            data_feat.append(np.array((V + 1) * [0.0], dtype="float32"))
        else:
            duration = normalized_duration[j]
            packet = normalized_packet[j]
            data_gen.append(1.0)
            d = V * [0.0]
            d[packet] = 1.0
            d.append(duration)
            data_feat.append(np.array(d, dtype="float32"))
    data_gen_flag.append(np.array(data_gen, dtype="float32"))
    data_feature.append(np.array(data_feat))
    data_attribute.append(np.array(data_attr, dtype="float32"))

print(D)
print(V)

data_feature = np.array(data_feature)
print(data_feature.shape)
data_attribute = np.array(data_attribute)
print(data_attribute.shape)
data_gen_flag = np.array(data_gen_flag)
print(data_gen_flag.shape)
print("Max Duration")
print(max_duration)

np.savez("data/iot/data_train.npz", data_feature=data_feature, data_attribute=data_attribute, data_gen_flag=data_gen_flag)
with open('data/iot/data_feature_output.pkl', 'wb') as fp:
    pickle.dump(data_feature_output, fp, protocol=2)
with open('data/iot/data_attribute_output.pkl', 'wb') as fp:
    pickle.dump(data_attribute_output, fp, protocol=2)