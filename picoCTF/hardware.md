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


# 2. I like logic
i like logic and i like files, apparently, they have something in common, what should my next step be.
Attached is a challenge.sal file

## Solution
This challenge required us to install logic2 from saleae. Placing the challenge file under logic2, we open its capture, export a .csv file and see that in channel 3 there is a significant amount of data. We use a UART analyser here (async serial) and calibrate it to default conditions, with baudrate as 9600. Looking into channel 3 we get the following 

![](IMAGES/saleae.png "File capture in logic2 at channel 3 after UART protocol analysis")

In the midst of this data, we find the flag

## Flag:
```
FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925} ⁠
```

## Concepts learnt
Saleae Logic Analyzer is a small hardware device (and software) used to “listen” to electronic signals—basically digital voltages that go HIGH (1) or LOW (0).
UART stands for Universal Asynchronous Receiver/Transmitter which is used to transfer data amongst electonics. This analyser selected also has a baud rate, which defines how fast the bits are sent between the two ports. In the capture, channel 3 had a fast toggling signal while the others were flat which is a classic sign of UART data. 

## Notes
This challenge was tough to say the least, for some reason here I became perhaps inept to solve anything and begain converting the .sal file to zip and tring to analyse the .bin files under the .sal. Giving me nothing of note. Then I began trying to install logic2 only to immediately not even try analysing anything and assume something was from my system. I have no idea why I was so off today but that's that.

## References
https://en.wikipedia.org/wiki/Logic_analyzer
https://www.geeksforgeeks.org/computer-networks/universal-asynchronous-receiver-transmitter-uart-protocol/
https://www.youtube.com/watch?v=Ak9R4yxQPhs

