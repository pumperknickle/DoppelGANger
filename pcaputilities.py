import pyshark
import math
import statistics
from sklearn.cluster import DBSCAN
import random
import csv


def extract_all(real_packet_sizes_file):
    """
    Extract packet sequences from file of signed ints.
    Sign indicates direction
    # Arguments:
        real_packet_sizes_file: String
            path to file
    # Returns:
        normalized_packets: 2D list of unsigned ints
        V: vocab size
    """
    real_packets = extractSequences(real_packet_sizes_file)
    normalized_packets = []
    max_packet_size = 0
    for packets in real_packets:
        print(packets)
        max_packet_size = max(max([abs(int(x)) for x in packets]), max_packet_size)
    V = max_packet_size * 2
    for packets in real_packets:
        packet_sizes = [(int(x) + max_packet_size) for x in packets]
        normalized_packets.append(packet_sizes)
    return normalized_packets, V+1


def most_common(lst):
    return max(set(lst), key=lst.count)


def save_sequence(filename, sequence):
    with open(filename, 'a', newline='\n') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=' ')
        csv_writer.writerow(sequence)


def signature_sample(signature):
    samples = []
    for constraints in signature:
        sample = random.randint(constraints[0], constraints[1])
        samples.append(sample)
    return samples


def sequence_sample(sequence):
    samples = []
    for step in sequence:
        if isinstance(step, int):
            samples.append(step)
        else:
            samples = samples + signature_sample(stringToSignature(step))
    return samples


def sequences_sample(sequences):
    samples = []
    for sequence in sequences:
        samples.append(sequence_sample(sequence))
    return samples


def convert_to_durations(pathToFile):
    pcaps = pyshark.FileCapture(pathToFile)
    pcaps.set_debug()
    tuples = []
    for pcap in pcaps:
        if 'IP' in pcap and 'TCP' in pcap and 'TLS' not in pcap:
            tuples.append(float(pcap.frame_info.time_epoch))
        else:
            if 'TLS' in pcap and 'TCP' in pcap and 'IP' in pcap:
                try:
                    tlsPCAP = getattr(pcap.tls, 'tls.record.content_type')
                    if tlsPCAP == 23:
                        tuples.append(float(pcap.frame_info.time_epoch))
                except:
                    print("TLS did not have content type attribute!")
    pcaps.close()
    final_durations = []
    for i in range(len(tuples) - 1):
        final_durations.append(tuples[i + 1] - tuples[i])
    final_durations.append(0)
    return final_durations


def get_activity_order(all_sequences, all_signatures):
    signatureDictionary = dict()
    singleDictionary = dict()
    for size, signatures in all_signatures.items():
        for i in range(len(signatures)):
            signature = signatures[i]
            count = 0
            for sequence in all_sequences:
                ngramSeq = ngrams(size, sequence)
                idx = 0
                while idx <= len(ngramSeq) - size:
                    ngram = ngramSeq[idx]
                    if matches(ngram, signature):
                        count += size
                        idx += size
                    else:
                        idx += 1
            stringSig = signatureToString(signature)
            if len(signature) == 1:
                singleDictionary[stringSig] = count
            else:
                signatureDictionary[stringSig] = count
    return sorted(signatureDictionary.items(), key=lambda x: x[1], reverse=True)[0:100] + sorted(singleDictionary.items(), key=lambda x: x[1], reverse=True)[0:100]


def all_greedy_activity_conversion(all_sequences, all_signatures):
    sorted_sigs = get_activity_order(all_sequences, all_signatures)
    all_converted = []
    for sequence in all_sequences:
        all_converted.append(greedy_activity_conversion(sequence, sorted_sigs))
    return all_converted


def extract_dictionaries_from_activities(converted):
    sigset = set()
    for c in converted:
        sigset = sigset.union(c)
    signatureToToken = {k: v for v, k in enumerate(list(sigset))}
    tokenToSignature = {v: k for k, v in signatureToToken.items()}
    return signatureToToken, tokenToSignature


def chunk_and_convert_ps(sequences, sig_sequences, chunk):
    all_ps = []
    all_sig = []
    for i in range(len(sig_sequences)):
        idx = 0
        sequence = sequences[i]
        sig_sequence = sig_sequences[i]
        for j in range(math.floor(len(sig_sequence)/chunk)):
            starting_chunk = j * chunk
            ps = []
            sigs = []
            for k in range(chunk):
                sig = sig_sequence[starting_chunk + k]
                sigs.append(sig)
                if isinstance(sig, int):
                    ps += sequence[idx:idx+1]
                    idx += 1
                else:
                    sig_length = len(stringToSignature(sig))
                    ps += sequence[idx:idx+sig_length]
                    idx += sig_length
            all_sig.append(sigs)
            all_ps.append(ps)
    return all_ps, all_sig


def chunk_and_convert_ps_and_durations(sequences, durations, sig_sequences, chunk):
    all_ps = []
    all_raw_duration = []
    all_duration = []
    all_sig = []
    for i in range(len(sig_sequences)):
        idx = 0
        sequence = sequences[i]
        duration_sequence = durations[i]
        sig_sequence = sig_sequences[i]
        for j in range(math.floor(len(sig_sequence)/chunk)):
            starting_chunk = j * chunk
            ps = []
            raw_duration = []
            duration = []
            sigs = []
            for k in range(chunk):
                sig = sig_sequence[starting_chunk + k]
                sigs.append(sig)
                if isinstance(sig, int):
                    ps += sequence[idx:idx+1]
                    duration.append(duration_sequence[idx])
                    raw_duration.append(duration_sequence[idx])
                    idx += 1
                else:
                    sig_length = len(stringToSignature(sig))
                    ps += sequence[idx:idx+sig_length]
                    duration.append(sum(duration_sequence[idx:idx+sig_length]))
                    raw_duration += duration_sequence[idx:idx+sig_length]
                    idx += sig_length
            all_sig.append(sigs)
            all_ps.append(ps)
            all_duration.append(duration)
            all_raw_duration.append(raw_duration)
    return all_ps, all_raw_duration, all_duration, all_sig

def greedy_activity_conversion(sequence, sorted_signatures):
    if len(sequence) == 0:
        return []
    if len(sorted_signatures) == 0:
        return sequence
    signature_tuple = sorted_signatures[0]
    signatureString = signature_tuple[0]
    signature = stringToSignature(signatureString)
    idx = 0
    while idx <= (len(sequence) - len(signature)):
        if matches(sequence[idx:idx + len(signature)], signature):
            return greedy_activity_conversion(sequence[0:idx], sorted_signatures[1:len(sorted_signatures)]) + [
                signatureString] + greedy_activity_conversion(sequence[idx + len(signature):len(sequence)],
                                                              sorted_signatures)
        else:
            idx += 1
    return greedy_activity_conversion(sequence, sorted_signatures[1:len(sorted_signatures)])


def convertToFeatures(pathToFile):
    pcaps = pyshark.FileCapture(pathToFile)
    pcaps.set_debug()
    tuples = []
    for pcap in pcaps:
        if 'IP' in pcap and 'TCP' in pcap and 'TLS' not in pcap:
            tuples.append([pcap.ip.src, pcap.ip.dst, pcap.length])
        else:
            if 'TLS' in pcap and 'TCP' in pcap and 'IP' in pcap:
                try:
                    tlsPCAP = getattr(pcap.tls, 'tls.record.content_type')
                    if tlsPCAP == 23:
                        tuples.append([pcap.ip.src, pcap.ip.dst, pcap.length])
                except:
                    print("TLS did not have content type attribute!")
    pcaps.close()
    sources = [row[0] for row in tuples]
    destinations = [row[1] for row in tuples]
    if not sources and not destinations:
        return []
    most_common_ip = most_common(sources + destinations)
    features = []
    for row in tuples:
        if row[0] == most_common_ip:
            length = int(row[2])
            features.append(length)
        else:
            length = int(row[2]) * -1
            features.append(length)
    return features


def ngrams(n, sequence):
    output = []
    for i in range(len(sequence) - n + 1):
        output.append(sequence[i:i + n])
    return output


def isPingPong(sequence):
    for i in range(len(sequence) - 1):
        if sequence[i] > 0 and sequence[i + 1] > 0:
            return False
        if sequence[i] < 0 and sequence[i + 1] < 0:
            return False
    return True


def countngrams(sequences):
    counts = dict()
    for i in sequences:
        counts[tuple(i)] = counts.get(tuple(i), 0) + 1
    return counts


def similarity(x, y, coefficient_of_variation_threshold):
    coefficients_of_variations = []
    for i in len(x):
        mean = (x.get(i, 0) + y.get(i, 0)) / 2
        variance = ((x.get(i, 0) - mean) ** 2) + ((y.get(i, 0) - mean) ** 2)
        standard_dev = math.sqrt(variance)
        coefficients_of_variations.append(float(standard_dev) / mean)
    return statistics.mean(coefficients_of_variations) < coefficient_of_variation_threshold


def dbclustermin(x, eps, min_samples):
    db = DBSCAN(eps, min_samples).fit(x)
    clusters = dict()
    for i in range(len(db.labels_)):
        if db.labels_[i] != -1:
            clusters[db.labels_[i]] = clusters.get(db.labels_[i], []) + [x[i]]
    return list(clusters.values())


# Cluster using dbscan
def dbcluster(x, eps, samples_ratio):
    min_samples = math.floor(len(x) / float(samples_ratio))
    db = DBSCAN(eps, min_samples).fit(x)
    clusters = dict()
    for i in range(len(db.labels_)):
        if db.labels_[i] != -1:
            clusters[db.labels_[i]] = clusters.get(db.labels_[i], []) + [x[i]]
    return list(clusters.values())


# Extract Signatures from cluster
def extractSignatures(clusters, n):
    signatures = []
    for cluster in clusters:
        signature = []
        for i in range(n):
            column = []
            for seq in cluster:
                column.append(seq[i])
            signature.append((min(column), max(column)))
        signatures.append(signature)
    return signatures


def matches(ngram, signature):
    if len(ngram) != len(signature):
        return False
    for i in range(len(ngram)):
        ngramElement = ngram[i]
        signatureElement = signature[i]
        sigMin = signatureElement[0]
        sigMax = signatureElement[1]
        if ngramElement < sigMin or ngramElement > sigMax:
            return False
    return True


def generate_from_sig(signature):
    generated = []
    for tuple in signature:
        generated.append(random.randint(tuple[0], tuple[1]))
    return generated


def extractFeatures(ngrams, signatures):
    features = []
    for signature in signatures:
        count = 0
        for ngram in ngrams:
            if matches(ngram, signature):
                count += 1
        frequency = 0 if len(ngrams) == 0 else (count) / float(len(ngrams))
        features.append(frequency)
    return features


def signatureCount(all_signatures):
    all_sigs = 0
    for count, signatures in all_signatures.items():
        all_sigs += len(signatures)
    return all_sigs


def signatureExtractionAll(sequences, minSigSize, maxSigSize, distance_threshold, cluster_threshold):
    all_signatures = dict()
    for i in range(minSigSize, maxSigSize + 1):
        allngrams = []
        for sequence in sequences:
            ngramVector = ngrams(i, sequence)
            for ngram in ngramVector:
                allngrams.append(ngram)
        cluster = dbclustermin(allngrams, distance_threshold, cluster_threshold)
        signatures = extractSignatures(cluster, i)
        all_signatures[i] = signatures
    return all_signatures


def featureExtractionAll(sequences, all_signatures):
    signatureFeatures = [None] * len(sequences)
    for i in range(len(sequences)):
        signatureFeatures[i] = featureExtraction(sequences[i], all_signatures)
    return signatureFeatures


def featureExtraction(sequence, all_signatures):
    all_features = []
    for i, signatures in all_signatures.items():
        ngramVector = ngrams(i, sequence)
        newFeatures = extractFeatures(ngramVector, signatures)
        all_features = all_features + newFeatures
    return all_features


def expandExtractAll(sequences, all_signatures):
    signature_features = []
    for sequence in sequences:
        signature_features = signature_features + expandAndExtract(sequence, all_signatures)
    return signature_features


def expandAndExtract(sequence, all_signatures):
    all_features = []
    counts = dict()
    for sig_length, signatures in all_signatures.items():
        counts[sig_length] = [0] * len(signatures)
    for i in range(len(sequence)):
        for sig_length, signatures in all_signatures.items():
            if sig_length <= i + 1:
                ngram = sequence[i + 1 - sig_length:i + 1]
                for j in range(len(signatures)):
                    signature = signatures[j]
                    if matches(ngram, signature):
                        counts[sig_length][j] += 1
        feature = []
        for sig_length, c in counts.items():
            v = [(float(0) if x is 0 else float(x) / float(i - sig_length + 2)) for x in c]
            feature = feature + v
        all_features.append(feature)
    return all_features


def signatureToString(signature):
    signature_ints = []
    for tuple in signature:
        signature_ints.append(tuple[0])
        signature_ints.append(tuple[1])
    return ', '.join(str(x) for x in signature_ints)


def stringToSignature(item):
    item.replace(" ", "")
    arr = item.split(',')
    int_arr = [int(numeric_string) for numeric_string in arr]
    sig = []
    for i in range(0, len(int_arr), 2):
        sig.append((int_arr[i], int_arr[i + 1]))
    return sig

def extractSequences(filename):
    sequences = []
    with open(filename, newline='\n') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=' ')
        for row in csv_reader:
            sequences.append(row)
    return sequences
