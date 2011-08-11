jQuery Password Entropy
=======================

This jQuery plug-in is built to give an estimate of the entropy of a password.
Initial calculations assume a randomly generated password is used, and then
applies a heuristics approach to penalize some common problems that arise
with human-generated passwords.

Some of the patterns used for creating the estimates are based on data collected
in the paper "Testing Metrics for Password Creation Policies by Attacking Large 
Sets of Revealed Passwords" by Weir et. al. and can be recommended as further
reading for those interested.

The default blacklisted passwords are based on lists downloaded from
http://www.skullsecurity.org/ and then compiled to match the purpose of this
plug-in.

Created by Erik Brännström.


Options
-------

- display       : Selector for the element to display strength.
- functions     : Array of functions that receive the current entropy and password.
                  Must return a value that will replace the current value.
                  Options are merged with defaults.
- strings       : Array with six elements, setting the result string.
- classes       : Array with six elements, setting the class of the display element
                  based on the strength.
- blacklist     : Array containing blacklisted words that should not be used as
                  passwords. Options are merged with defaults.

Example
-------
`$('input[type=password]').passwordEntropy({
    'display' : 'div.result'
});`

License
-------
Copyright (C) 2011 by Erik Brännström

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.