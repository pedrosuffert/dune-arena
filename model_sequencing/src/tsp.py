import itertools
import numpy as np

def order_blocks_with_tsp(costMatrix_FP, cost_F1, print_gap=False):
    '''
    Exact replacement for the MILP TSP (DUNE) — for the small cluster counts in DUNE,
    brute-forces the minimum linear ordering. Semantics identical to the original:
      cost[i][j] = costMatrix_FP[j][i] * (1 - cost_F1[i]/100)   # cost of i preceding j
    minimise the sum of cost over all ordered (precedes) pairs; return 0-based cluster
    sequence, best (precedes-most) first.
    '''
    n = costMatrix_FP.shape[0]
    cost = np.zeros((n, n))
    for i in range(n):
        for j in range(n):
            cost[i][j] = costMatrix_FP[j][i] * (1 - cost_F1[i] / 100) if i != j else np.inf

    best_seq, best_cost = None, np.inf
    for perm in itertools.permutations(range(n)):
        c = 0.0
        for a in range(n):
            for b in range(a + 1, n):
                c += cost[perm[a]][perm[b]]   # perm[a] precedes perm[b]
        if c < best_cost:
            best_cost, best_seq = c, perm
    if print_gap:
        print(0.0)
    return list(best_seq)
