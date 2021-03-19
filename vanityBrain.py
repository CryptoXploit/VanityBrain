#!/usr/bin/env python

from argparse import ArgumentParser
from coinkit import BitcoinKeypair
import io
from logging import info, basicConfig, INFO, error
from sys import exit
from random import sample
from old_mnemonic import words as old_word_list
from old_mnemonic import mn_decode, OldAccount

def isVanity(seed, prefix, ignoreCase = False):
	key = BitcoinKeypair.from_passphrase(seed)
	if ignoreCase:
		return key.address().lower().startswith(prefix)
	else:
		return key.address().startswith(prefix)

def findVanityInDic(fileName, prefix, maxTries = 0, length = 3, ignoreCase = False):
	if maxTries == 0:
		maxTries = 60**len(prefix)
	dictionary_encoding = "utf-8"
	info("Opening dictionary file {} and validating encoding is {}".format(fileName, dictionary_encoding))
	try:
		f_dictionary = io.open(fileName, 'rt', encoding=dictionary_encoding)
		words = f_dictionary.readlines()
		f_dictionary.close()
	except Exception as e:
		error("Failed to open dictionary file {}. Make sure file is {} encoded.".format(
						fileName, dictionary_encoding))
		exit(1)
	info("finished reading file {}, starting bruteforce...".format(fileName))
	for i in range(maxTries):
		guess = ''.join(sample(words, length)).replace('\n', ' ')
		if isVanity(guess, prefix, ignoreCase):
			return guess, BitcoinKeypair.from_passphrase(guess).address()
	return None

def findVanity4OldElectrum(prefix,  maxTries = 0, ignoreCase = False):
	if maxTries == 0:
		maxTries = 60**len(prefix)
	for i in range(maxTries):
		guess = sample(old_word_list,12)
		seed = mn_decode(guess)
		mpk = OldAccount.mpk_from_seed(seed)
		acc = OldAccount({'mpk':mpk, 0:[], 1:[]})
		addr = acc.create_new_address(False)
		if ignoreCase:
			if addr.lower().startswith(prefix):
				return ' '.join(guess), addr
		else:
			if addr.startswith(prefix):
				return ' '.join(guess), addr
	return None


def main():
	argParser = ArgumentParser(description='A script to find vanity address with seed of a givven parameters.',
								usage='python vanityBrain.py <vanity address starting> [args]',
								epilog='in default, this script looks for 12 words electrum compatible seed')
	argParser.add_argument('prefix', action='store', nargs=1,
							help='prefix of desired address, (not including the starting 1)')
	argParser.add_argument('-n', action='store_false', dest='electrumOld', default=True,
							help='dont use electrum compatible search')
	argParser.add_argument('-d',  action='store', dest='dictFile', default='bip39.txt',
							help='dictionary file to take passphrase from')
	argParser.add_argument('-l', action='store', dest='length',type=int, default=12,
							help='length of desired passphrase')
	argParser.add_argument('-t',   action='store', dest='maxTries', type=int, default=0,
							help='maximum number of tries')
	argParser.add_argument('-i', action='store_true', dest='ignoreCase', default=False,
							help='case-insensitive vanity address search')
	argParser.add_argument('--version', action='version', version='%(prog)s 1.1')
	args= argParser.parse_args()
	
	basicConfig(level=INFO,
						format='%(message)s')

	if(args.ignoreCase):
		prefix='1'+''.join(args.prefix).lower()
	else:
		prefix='1'+''.join(args.prefix)
	info('looking for addresses starting with {}:'.format(prefix))

	if args.electrumOld:
		seed, addr=findVanity4OldElectrum(prefix, args.maxTries, args.ignoreCase)
	else:
		seed, addr=findVanityInDic(args.dictFile, prefix, args.maxTries, args.length, args.ignoreCase)
	info('your new key is: {}\nand your address is: {}'.format(seed, addr))
	

if __name__ == '__main__':
	main()