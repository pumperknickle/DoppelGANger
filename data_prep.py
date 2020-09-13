from gan.output import Output, OutputType, Normalization
from pcaputilities import chunk_and_convert_to_training, convertToFeatures, sequences_sample, chunk_and_convert_ps_and_durations, extract_dictionaries_from_activities, convert_to_durations, signatureExtractionAll, all_greedy_activity_conversion, chunk_and_convert_ps
import sys
import glob
import numpy as np
import pickle
import random
import csv


def normalize_packet_sizes(sequences):
    normalized_packets = []
    num_seqs = []
    max_packet_size = 0
    for sequence in sequences:
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

all_signatures = signatureExtractionAll(normalized_p, 1, 7, 5, 4)
results = all_greedy_activity_conversion(normalized_p, all_signatures)
signatureToTokens, tokensToSignatures = extract_dictionaries_from_activities(results)

V = len(tokensToSignatures)

with open("sigToToken.pkl", mode='wb') as sigFile:
    pickle.dump(signatureToTokens, sigFile)
with open("tokenToSig.pkl", mode='wb') as tokenFile:
    pickle.dump(tokensToSignatures, tokenFile)

print("signature to tokens")
print(signatureToTokens)
print("tokens to signature")
print(tokensToSignatures)

seq_length = 20

sequences = []
for sequence in results:
    sigs = []
    for token in sequence:
        sigs.append(signatureToTokens[token])
    sequences.append(sigs)

r = chunk_and_convert_ps_and_durations(normalized_p, durations, results, seq_length)
packet_sizes = r[0]


for i in range(len(packet_sizes)):
  filename = 'real_packet_sizes.txt'
  with open(filename, mode='a') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    c_ps = packet_sizes[i]
    csv_writer.writerow(c_ps)

raw_duration = r[1]
sig_duration = r[2]
signatures = r[3]

for i in range(len(raw_duration)):
  filename = 'real_durations.txt'
  with open(filename, mode='a') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    c_d = raw_duration[i]
    csv_writer.writerow(c_d)

all_tokens = []
for signature in signatures:
    tokens = []
    for sig in signature:
        tokens.append(signatureToTokens[sig])
    all_tokens.append(tokens)

sig_duration, max_duration = normalize_durations(sig_duration)

minDicts = dict()
maxDicts = dict()

minDicts[0] = 10000000
maxDicts[0] = 0

def divide_chunks(l, n):
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]

all_chunks = []
all_altered_chunks = []

for i in range(len(normalized_p)):
  filename = 'real_data4.csv'
  with open(filename, mode='a') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    chunks = divide_chunks(normalized_p[i], seq_length)
    for chunk in chunks:
      all_chunks.append(chunk)
      if len(chunk) == seq_length:
        csv_writer.writerow(chunk)


for i in range(len(sequences)):
  filename = 'real_data3.csv'
  with open(filename, mode='a') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    chunks = divide_chunks(sequences[i], seq_length)
    for chunk in chunks:
      all_chunks.append(chunk)
      if len(chunk) == seq_length:
        new_list = [x for x in chunk]
        csv_writer.writerow(new_list)


def extractSequences(fn):
    seqs = []
    with open(fn, newline='\n') as csvf:
        csv_reader = csv.reader(csvf, delimiter=' ')
        for row in csv_reader:
            seqs.append(row)
    return seqs
#
# mapping = dict()
# real_all_seq = extractSequences("real_data.csv")
# for i in range(len(real_all_seq)):
#     print("real")
#     print(len(real_all_seq[i]))
#     print(real_all_seq[i])
#     print("altered")
#     print(len(all_altered_chunks[i]))
#     print(all_altered_chunks[i])
#     zipped = dict(zip(real_all_seq[i], all_altered_chunks[i]))
#     mapping.update(zipped)
#
# real_sequences = []
# for real_seq in all_chunks:
#     real_sequence = []
#     for idx in real_seq:
#         real_sequence.append(tokensToSignatures[idx])
#     real_sequences.append(real_sequence)
#
# final_reals = sequences_sample(real_sequences)
#
# for i in range(len(final_reals)):
#   chunks = divide_chunks(final_reals[i], seq_length)
#   for chunk in chunks:
#     if min(chunk) < minDicts[0]:
#       minDicts[0] = min(chunk)
#     if max(chunk) > maxDicts[0]:
#       maxDicts[0] = max(chunk)
#
# for i in range(len(final_reals)):
#   filename = 'real_datac.txt'
#   with open(filename, mode='a') as csvfile:
#     csv_writer = csv.writer(csvfile, delimiter=' ')
#     alteredChunk = list(map(lambda x: x - minDicts[0], final_reals[i]))
#     csv_writer.writerow(alteredChunk)
#
# fake_seqs = extractSequences("fake_data.txt")
# fake_sequences = []
# for fake_seq in fake_seqs:
#     fake_sequence = []
#     for idx in fake_seq:
#         fake_sequence.append(tokensToSignatures[mapping[idx]])
#     fake_sequences.append(fake_sequence)
#
# final_fakes = sequences_sample(fake_sequences)
#
# for i in range(len(final_fakes)):
#   chunks = divide_chunks(final_fakes[i], seq_length)
#   for chunk in chunks:
#     if min(chunk) < minDicts[0]:
#       minDicts[0] = min(chunk)
#     if max(chunk) > maxDicts[0]:
#       maxDicts[0] = max(chunk)
#
# for i in range(len(final_fakes)):
#   filename = 'fake_datac.txt'
#   with open(filename, mode='a') as csvfile:
#     csv_writer = csv.writer(csvfile, delimiter=' ')
#     alteredChunk = list(map(lambda x: x - minDicts[0], final_fakes[i]))
#     csv_writer.writerow(alteredChunk)

train_X, train_y = chunk_and_convert_to_training(signatures, raw_duration, max_duration, signatureToTokens, 7)
print(train_X)
print(train_y)

print(len(train_X))
print(len(train_y))


data_feature_output = [
    Output(type_=OutputType.DISCRETE, dim=V, normalization=None, is_gen_flag=False),
    Output(type_=OutputType.CONTINUOUS, dim=1, normalization=Normalization.ZERO_ONE, is_gen_flag=False)
]

data_attribute_output = [
   Output(type_=OutputType.DISCRETE, dim=1, normalization=None, is_gen_flag=False)
]


data_feature = []
data_attribute = []
data_gen_flag = []


for i in range(len(all_tokens)):
    packet_size = all_tokens[i]
    normalized_duration = sig_duration[i]
    label = 0
    data_gen = []
    data_feat = []
    data_attr = [0] * 1
    data_attr[label] = 1.0
    for j in range(seq_length):
        duration = normalized_duration[j]
        packet = packet_size[j]
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
with open("train_X.pkl", mode='wb') as sigFile:
    pickle.dump(train_X, sigFile)
with open("train_y.pkl", mode='wb') as tokenFile:
    pickle.dump(train_y, tokenFile)
with open("max_duration.pkl", mode='wb') as tokenFile:
    pickle.dump(max_duration, tokenFile)
with open('data/iot/data_feature_output.pkl', 'wb') as fp:
    pickle.dump(data_feature_output, fp, protocol=2)
with open('data/iot/data_attribute_output.pkl', 'wb') as fp:
    pickle.dump(data_attribute_output, fp, protocol=2)
