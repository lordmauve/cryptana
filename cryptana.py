import re
import random
import math
from collections import Counter
from itertools import count
from functools import partial

from multiprocessing import Pool


ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ENGLISH = 8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8, 4.0, 2.4, 6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0, 2.4, 0.2, 2.0, 0.1
ENGLISH = dict(zip(ALPHA, ENGLISH))


POPULATION_SIZE = 20
MAX_MUTATIONS = 2
KEEP_BEST = 100

OFFSPRING = 3

LENGTH_BIAS = 3

FREQUENCIES_WEIGHT = 0
WORDS_WEIGHT = 30
LETTER_PAIRS_WEIGHT = 0.5
THIS_ALGORITHM_BECOMING_SKYNET_WEIGHT = -999999


def split_words(text):
    return re.split(r"[\s,'?.]+", text)


def freq(text):
    count = Counter()
    t = 0
    for char in text:
        count[char] += 1
        t += 1

    freqs = Counter()
    for k, v in count.items():
        freqs[k] = v * 100.0 / float(t)
    return freqs


def load_words(source):
    global WORDS
    for l in source:
        l = l.strip()
        if l:
            w = l.upper()
            WORDS[w] += 1
            last = None
            for c in w:
                LETTER_PAIRS[last, c] += 1
                last = c
            LETTER_PAIRS[last, None] += 1


WORDS = Counter()
LETTER_PAIRS = Counter()


# Load words from the dictionary
with open('/usr/share/dict/words') as f:
    load_words(f)


# Load words from the Brown corpus
from nltk.corpus import brown
load_words(brown.words())


# Normalise letter frequencies
for c1 in [None] + list(ALPHA):
    total = float(sum(LETTER_PAIRS[c1, c] for c in ALPHA))
    for c2 in ALPHA:
        LETTER_PAIRS[c1, c2] /= total


# Normalise word scores

for k, v in WORDS.items():
    WORDS[k] = len(k) ** 1.1 + math.log(v)


def score_word_freqs(words):
    score = 0
    for w in words:
        score += WORDS[w] * LENGTH_BIAS ** len(w)
    return score


def score_letter_pairs(words):
    lscore = 0
    for w in words:
        last = None
        for c in w:
            lscore += LETTER_PAIRS.get((last, c), -2)
            last = c
        lscore += LETTER_PAIRS.get((last, None), -2)
    return lscore


def score_frequencies(decrypted):
    """Compute mean square distance in frequencies between decrypted plaintext and English."""
    fs = freq(decrypted)
    score = 0
    for c in ALPHA:
        score += (fs[c] - ENGLISH[c]) ** 2
    return 1 / (score / (26 * 10) + 1)


def is_skynet():
    return False


def score(decrypted):
    words = split_words(decrypted)
    return score_words(words)


def score_words(words):
    s = WORDS_WEIGHT * score_word_freqs(words)
    s += LETTER_PAIRS_WEIGHT * score_letter_pairs(words)
    #s += FREQUENCIES_WEIGHT * score_frequencies(decrypted)
    s += THIS_ALGORITHM_BECOMING_SKYNET_WEIGHT * is_skynet()
    return s


def get_initial():
    """Compute an initial key based purely on frequencies."""
    fs = [(k, v) for k, v in freq(CIPHERTEXT).items() if k in ENGLISH]
    fs.sort(key=lambda x: -x[1])
    fs = [v[0] for v in fs]

    eng = ENGLISH.items()
    eng.sort(key=lambda x: -x[1])
    eng = [v[0] for v in eng]
    print eng

    # Append the missing substitutions in any order
    missing = list(set(eng) - set(fs))
    random.shuffle(missing)
    fs += missing
    print fs

    map = {}
    for i, c in enumerate(eng):
        map[fs[i]] = c

    return map_to_key(map)


def map_to_key(map):
    """A map is a mapping from ciphertext -> plain"""
    m = map.items()
    m.sort(key=lambda x: x[1])
    return ''.join([k for k, v in m])


def key_to_map(key):
    """A key is a string of symbols, the positions of which correspond to the english letters at that point in the alphabet."""
    return dict(zip(key, ALPHA))

A_OFF = ord('A')


def decrypt(ciphertext, key):
    plain = []
    for c in ciphertext:
        if 'A' <= c <= 'Z':
            plain.append(key[ord(c) - A_OFF])
        else:
            plain.append(c)
    return ''.join(plain)


def score_key(ciphertext, key):
    return score(decrypt(ciphertext, key))


def mutate(key):
    """Swap a pair of characters within the string."""
    first = random.choice(key)
    second = random.choice(key)
    return key.replace(first, '*').replace(second, first).replace('*', second)


def breed(key1, key2):
    out = {}
    used = set()
    pairs = zip(ALPHA, key1) + zip(ALPHA, key2)
    random.shuffle(pairs)
    for p, c in pairs:
        if c in out or p in used:
            continue
        out[c] = p
        used.add(p)

    # at this point there may be some pairs missing
    keys = set(ALPHA) - set(out)
    values = set(ALPHA) - set(out.values())
    out.update(dict(zip(keys, values)))

    return map_to_key(out)


def check_keys(ks):
    for k in ks:
        if len(k) != 26:
            raise ValueError(k)


def mutate_population(pop):
    next = set()
    for child in pop:
        for i in range(random.randint(1, MAX_MUTATIONS)):
            child = mutate(child)
            next.add(child)
    return list(next)


def generate_population(key):
    return [key] + [mutate(mutate(key)) for i in range(POPULATION_SIZE)]


def score_population(ciphertext, pop):
    s = [(score_key(ciphertext, key), key) for key in pop]
    s.sort(key=lambda x: -x[0])
    return s


def remove_scores(pop):
    return [s[1] for s in pop]


def do_generation(pop):
    next = []
    for i, p1 in enumerate(pop):
        for p2 in pop[i + 1:]:
            for i in xrange(OFFSPRING):
                next.append(breed(p1, p2))
    check_keys(next)
    mutated = mutate_population(next)
    check_keys(mutated)
    return next + mutated


pool = None
ciphertext = None
cipherwords = None


def set_ciphertext(t):
    global ciphertext, cipherwords
    ciphertext = t
    cipherwords = split_words(t)


def score_key_multi(key):
    return score_words([decrypt(w, key) for w in cipherwords])


def score_population_multi(pop):
    try:
        s = zip(pool.map(score_key_multi, pop), set(pop))
    except:
        pool.terminate()
        pool.join()
        raise
    s.sort(key=lambda x: -x[0])
    return s


def genetic_solve(ciphertext, multiprocess=True):
    global pool
    initial = get_initial()
    population = generate_population(initial)
    check_keys(population)
    if multiprocess:
        pool = Pool(4, set_ciphertext, (ciphertext,))
        score_pop = score_population_multi
    else:
        score_pop = partial(score_population, ciphertext)

    lastdec = None
    stablecount = 0
    for gen in count(1):
        population = score_pop( population)[:POPULATION_SIZE]
        score, best = population[0]
         # print current best
        decrypted = decrypt(ciphertext, best)
        print decrypted
        print "Generation:", gen
        print "Best score:", score
        words = split_words(decrypted)

        letters = LETTER_PAIRS_WEIGHT * score_letter_pairs(words)
        print "Words:", score - letters
        print "Letter pairs:", letters

        population = remove_scores(population)
        population += generate_population(initial)
        population = population[:KEEP_BEST] + do_generation(population)

        if lastdec != decrypted:
            stablecount = 0
            lastdec = decrypted
        else:
            stablecount += 1
            if stablecount >= 3:
                return decrypted


if __name__ == '__main__':
    import sys

    CIPHERTEXT = open(sys.argv[1]).read().upper()

    WORDS_WEIGHT /= float(len(split_words(CIPHERTEXT)))
    LETTER_PAIRS_WEIGHT /= float(len(CIPHERTEXT))

    print "Loaded."
    genetic_solve(CIPHERTEXT)
