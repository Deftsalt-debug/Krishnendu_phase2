# Antakshari
Provided are two numpy files, one having 201 embedding vectors, 64 dims each and another containing 4 known edges connecting the actor nodes. 

## Flag
```
nite{Diehard_1891771341083729}
```

## Solution
Loading the files 

```py
import numpy as np

latent = np.load("latent_vectors.npy")     # shape (201, 64)
edges  = np.load("partial_edges.npy")      # shape (4, 2)

print(latent.shape)
print(edges)
```

We get:
latent shape: (201, 64)
edges shape: (4, 2)

Now writing a solver working off of a cosine rule 

```py
import numpy as np

latent = np.load("latent_vectors.npy").astype(float)
edges  = np.load("partial_edges.npy")
X = latent / (np.linalg.norm(latent, axis=1, keepdims=True) + 1e-12)

S = X @ X.T
np.fill_diagonal(S, -np.inf)

k = 6
topk = np.sort(S, axis=1)[:, -k:]
kth_best = topk[:, 0]

movie_node = int(np.argmax(kth_best))
print("Movie node:", movie_node)
print("Movie node 6th-best similarity:", kth_best[movie_node])

nbrs = np.argsort(S[movie_node])[::-1]
top6 = nbrs[:6]

print("Top 6 cast nodes:", top6.tolist())
print("Similarities:", S[movie_node, top6].tolist())

seq = sorted(top6.tolist(), reverse=True)
flag = "nite{" + "_".join(map(str, seq)) + "}"
print("FLAG:", flag)
```

Cosine similarity is:

cos(a,b)= (a . b) / (||a|| * ||b||)

If we normalize every vector so ||a|| = 1, then:

cos(a,b) = a . b

So after normalization, cosine similarity becomes just a dot product which is fast to compute for all pairs at once. 
This is what `X = latent / (np.linalg.norm(latent, axis=1, keepdims=True) + 1e-12)` does. (+ 1e-12 prevents division by zero as a safety guard)

We then build a similarity matrix which we list a score for each node (via cosine similarity and dot product) and finally list the ones whose neighbours have the best scores (exluding nodes in the diagonals of the matrix) which gives us our actor sequence.