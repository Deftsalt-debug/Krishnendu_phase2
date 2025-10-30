# 1. IQ-Test
Let your input x = 30478191278.

wrap your answer with nite{ } for the flag.

As an example, entering x = 34359738368 gives (y0, ..., y11), so the flag would be nite{010000000011}.

![](IMAGES/iqtest.png "Prompt image")

## Solution 
Manually plugging in the binary for x, we get this
`11100011000101001000100101010101110`

Now running through the entire logic gate sequence manually assigning each bit to x0,x1 and so on, we get the desired output and flag. 

## Flag
```
nite{100010011000}
```

## Concepts learnt
This was by essence a soild revision of logic gates, giving a good idea of repeating patterns and gate equations.

## Notes
i initially tried the lazy yet complicated route of trying to script a .py program to do the gate solving ourselves. Immediately relising I was way out of my depth here and giving up. If you're curious I'm more than happy to share how far I got. But yes I just decided to manually plug in the values and get the flag.

## References
https://www.geeksforgeeks.org/python/logic-gates-in-python/
https://www.geeksforgeeks.org/utilities/decimal-to-binary/


***

