import random
from prf import GGM_PRF
from prg_from_prf import PRG_from_PRF
from distinguisher import distinguishing_game, prg_from_prf_statistical_test, run_substitution_test

def main():

    prg_from_prf_statistical_test()
    distinguishing_game(q=100)
    run_substitution_test()


if __name__ == "__main__":
    main()