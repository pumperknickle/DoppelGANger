from pcaputilities import get_training
import pickle
import csv
from activityExpansion import extractSequences

tokens = extractSequences("generated_tokens.txt")

with open("tokenToSig.pkl", mode='rb') as tokenFile:
    tokensToSignatures = pickle.load(tokenFile)

predict_x = get_training(tokens, tokensToSignatures, 7)
with open("predict_X.pkl", mode='wb') as sigFile:
    pickle.dump(predict_x, sigFile)

