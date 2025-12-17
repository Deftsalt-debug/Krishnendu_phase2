# Floating point guardian
Provided is a ncat file.

## Flag
```
nite{br0_i5_n0t_g0nn4_b3_t4K1n6_any1s_j0bs_34x}
```

## Solution
The challenge provides us a easily predictable C program by which the author is trying to mimick a custom neural network whose auth gate is simple floats which we need to calculate the value of inividually. The “digital guardian” mentioned here is a fixed function that maps 15 numbers to 1 probability, and it accepts we're if that probability is within 1e-5 of a hard-coded target. 
Here src.c does the following 
Reads 15 doubles with scanf("%lf", &inputs[i]).
Computes probability = forward_pass(inputs);
Prints MASTER PROBABILITY: %.10f
Finally authenticates if:
|probability - 0.7331337420| < 10^(-5)

These activations on input elements depend on index modulo 4 which we see in the source file: 

i%4 == 0: `xor_activate(x, key)` — converts `x` to a fixed-point integer `long_val = (long)(x * 1_000_000)`, XORs with `key` (per-input constant), then converts back to double by dividing by `1e6`.
i%4 == 1: `tanh(x)`
i%4 == 2: `cos(x)`
i%4 == 3: `sinh(x / 10.0)`

So Q1, Q5, Q9, Q13 (indices 0,4,8,12) go through XOR.
Q2, Q6, Q10, Q14 go through tanh.
Q3, Q7, Q11, Q15 go through cos.
Q4, Q8, Q12 go through sinh(x/10).

Further from which the activated inputs use tan h each with variances in the number of passes.(hidden layers)

The XOR activation then performs the following 
- multiply by 1,000,000
- throw away the fractional part (C cast truncates toward 0)
- XOR the bits with a tiny key byte
- divide back down

This makes this gate not smooth: tiny changes in x can “jump” after truncation. 

After that the values are run through a sigmoid which squashes the value between (0,1) to resemble actual probability.

Now understanding how this works we write a .py script 

```py
#!/usr/bin/env python3
import math, random

GOAL = 0.7331337420
random.seed(1)

KEYS = [0x42, 0x13, 0x37, 0x99, 0x21, 0x88, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]

L1_W = [
    [0.523, -0.891, 0.234, 0.667, -0.445, 0.789, -0.123, 0.456],
    [-0.334, 0.778, -0.556, 0.223, 0.889, -0.667, 0.445, -0.221],
    [0.667, -0.234, 0.891, -0.445, 0.123, 0.556, -0.789, 0.334],
    [-0.778, 0.445, -0.223, 0.889, -0.556, 0.234, 0.667, -0.891],
    [0.123, -0.667, 0.889, -0.334, 0.556, -0.778, 0.445, 0.223],
    [-0.891, 0.556, -0.445, 0.778, -0.223, 0.334, -0.667, 0.889],
    [0.445, -0.123, 0.667, -0.889, 0.334, -0.556, 0.778, -0.234],
    [-0.556, 0.889, -0.334, 0.445, -0.778, 0.667, -0.223, 0.123],
    [0.778, -0.445, 0.556, -0.667, 0.223, -0.889, 0.334, -0.445],
    [-0.223, 0.667, -0.778, 0.334, -0.445, 0.556, -0.889, 0.778],
    [0.889, -0.334, 0.445, -0.556, 0.667, -0.223, 0.123, -0.667],
    [-0.445, 0.223, -0.889, 0.778, -0.334, 0.445, -0.556, 0.889],
    [0.334, -0.778, 0.223, -0.445, 0.889, -0.667, 0.556, -0.123],
    [-0.667, 0.889, -0.445, 0.223, -0.556, 0.778, -0.334, 0.667],
    [0.556, -0.223, 0.778, -0.889, 0.445, -0.334, 0.889, -0.556],
]
L1_B = [0.1, -0.2, 0.3, -0.15, 0.25, -0.35, 0.18, -0.28]

L2_W = [
    [0.712, -0.534, 0.823, -0.445, 0.667, -0.389],
    [-0.623, 0.889, -0.456, 0.734, -0.567, 0.445],
    [0.534, -0.712, 0.389, -0.823, 0.456, -0.667],
    [-0.889, 0.456, -0.734, 0.567, -0.623, 0.823],
    [0.445, -0.667, 0.823, -0.389, 0.712, -0.534],
    [-0.734, 0.623, -0.567, 0.889, -0.456, 0.389],
    [0.667, -0.389, 0.534, -0.712, 0.623, -0.823],
    [-0.456, 0.823, -0.667, 0.445, -0.889, 0.734],
]
L2_B = [0.05, -0.12, 0.18, -0.08, 0.22, -0.16]

OUT_W = [[0.923], [-0.812], [0.745], [-0.634], [0.856], [-0.723]]
OUT_B = [0.42]

def xor_step(x, k):
    u = int(x * 1_000_000) ^ k
    return u / 1_000_000.0

def mix(i, x):
    r = i & 3
    if r == 0: return xor_step(x, KEYS[i])
    if r == 1: return math.tanh(x)
    if r == 2: return math.cos(x)
    return math.sinh(x / 10.0)

def score(vec):
    h = []
    for j in range(8):
        s = sum(mix(i, vec[i]) * L1_W[i][j] for i in range(15)) + L1_B[j]
        h.append(math.tanh(s))
    g = []
    for j in range(6):
        s = sum(h[i] * L2_W[i][j] for i in range(8)) + L2_B[j]
        g.append(math.tanh(s))
    z = sum(g[i] * OUT_W[i][0] for i in range(6)) + OUT_B[0]
    return 1.0 / (1.0 + math.exp(-z))

def hunt(steps=120000):
    best_vec = [0.0] * 15
    for i in (0, 4, 8, 12): best_vec[i] = KEYS[i] / 1_000_000.0
    for i in (2, 6, 10, 14): best_vec[i] = math.pi / 2

    best_val = score(best_vec)
    best_gap = abs(best_val - GOAL)
    sigma = 1.0

    for t in range(steps):
        trial = best_vec[:]
        k = random.randrange(15)
        if (k & 3) == 0:
            trial[k] = max(0.0, trial[k] + random.randint(-30, 30) / 1_000_000.0)
        else:
            trial[k] += random.gauss(0.0, sigma)

        val = score(trial)
        gap = abs(val - GOAL)
        if gap < best_gap:
            best_vec, best_val, best_gap = trial, val, gap
        if t and t % 20000 == 0:
            sigma *= 0.7

    return best_vec, best_val, best_gap

if __name__ == "__main__":
    vec, val, gap = hunt()
    print("best prob:", val)
    print("err:", gap)
    print("\nInputs (Q1..Q15):")
    for x in vec:
        print(repr(x))
```

At a high level this script starts with an inital guess for each of the 15 inputs and then computes the probability of each of these guesses, twaking each portion until something fits closer to `GOAL`
Here, hunt() tries to find a vector vec such that score(vec) is close to GOAL. 
The inital declaration is to cleanse the XOR, essentially neutalising the XOR passes, Setting x = KEYS[i]/1e6 makes int(x*1e6) == KEYS[i] which on XOR with itself gives a 0. cos (pi/2) = 0 too so it neutalses the cos passes as well. The for loop then performs a hillclimbing procedure randomly picking indices and if it being 0, 4, 8 or 12, and then nudges the chosen input by at most ±0.00003. FOr the rest of the indices, it picks a random number from a bell curve whereaverage (center) is 0.0 and typical size is sigma. If sigma = 1.0, most changes are around -1 to +1 (but sometimes bigger).
Finally it evaluate these changes and compares it with the probablilty equation. It keeps this only if the soluton gets closer to the probability, otherwise reruns with previous iteration. At last, we tweak sigma to become 70% of what it was.
Sorta of a brute force script but I'm disguising it as a hillclimb. Lots of learning here, fun solve.

Grabbing the inputs, we just copy paste it into the oracle in the ncat.