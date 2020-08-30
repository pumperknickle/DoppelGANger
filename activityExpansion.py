import pickle
import csv
import random
from pcaputilities import sequences_sample

def extractSequences(fn):
    seqs = []
    with open(fn, newline='\n') as csvf:
        csv_reader = csv.reader(csvf, delimiter=' ')
        for row in csv_reader:
            if len(row) > 0:
                seqs.append(row)
    return seqs

with open("tokenToSig.pkl", mode='rb') as tokenFile:
    tokensToSignatures = pickle.load(tokenFile)

print(tokensToSignatures)
print(tokensToSignatures[5])
#
# real_seqs = extractSequences("real_samples.txt")
#
# real_sequences = []
# for real_seq in real_seqs:
#     real_sequence = []
#     for idx in real_seq:
#         real_sequence.append(tokensToSignatures[int(idx)])
#     real_sequences.append(real_sequence)

fake_seqs = extractSequences("tokens.txt")

fake_sequences = []
for fake_seq in fake_seqs:
    fake_sequence = []
    for idx in fake_seq:
        fake_sequence.append(tokensToSignatures[int(idx)])
    fake_sequences.append(fake_sequence)

# fake_sequences = random.sample(fake_sequences, len(real_sequences))

# final_reals = sequences_sample(real_sequences)
final_fakes = sequences_sample(fake_sequences)

# for i in range(len(final_reals)):
#   filename = 'exanded_real_samples.txt'
#   with open(filename, mode='a') as csvfile:
#     csv_writer = csv.writer(csvfile, delimiter=' ')
#     csv_writer.writerow(final_reals[i])

for i in range(len(final_fakes)):
  filename = 'final_generated_packet_sizes.txt'
  with open(filename, mode='a') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    csv_writer.writerow(final_fakes[i])
