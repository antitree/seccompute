# 2026-03-19
## Default Profile Factoring
* Right now the system gives a score like 63/100 or 83/100
* But we don't factor in things like are you better than the default seccomp profile
* Therefore we need do a face-off that compares it to the default or makes a recommendation to use the defaul tone instead

# Letter Grading
* If we get a grade of 63/100, that doesn't look that bad. But it should. We need to give an overall letter grades like: A+ = 95 or above. 63 is D, <60 is F or sometehing like that

# Nuances
* There are some architectural nuances we should factor in
* For example, if you have a default ALLOW Policy, then you should lose 50% of the overall score
* If you've gone so far as creating conditionals for an argument, then that should give a bonus score of +10 since it implies that you're working hard at doing the right thing
* If you are blocking a category of system call that risks being multiplexed with another allowed system call (e.g. socket blocked but socketcall is not) then we should highlight that

# Attacks and bypasses
* We need to provide detailed attack methodologies for the scenarios where bypasses exist
* For example, if there's a risk to multiplexing via io_uring, then we should describe that bypass
* Or there's a risk of an architectural-level bypass by running this on arm vs x86 because a arm system call is allowed that isn't on x86 then that should be bad
* We want to provide guidance to attack as an offensive tool which makes it also good for defenders that want to find the practicality of the problems.

# Format support
* Right now we only support json. That makes it only useful for containres
* But K8s uses yaml and at it's core it uses bpf bytecode
* I've already written a tool that iwll convert bpfbytecode to JSON so I should extract the work from seccomp-diff and port it to seccompute
* Then users can convert in between all of them and share as a common language
* NOTE: To do this in bpfbytecode is challenging. We've done this before but it does'nt always clearly map and we should think about the architecture of this thing. It maybe be smartest to write at least this aspect of it in rust. 

# Be funny
* We have to accept that this isn't going to be that useful. But it could be funny
* I had an idea where instead of grading things, we describe the profiles as different D&D characters
* For example chaotic evil means that the profile allows dangerous things AND allows a whole bunch of unnecessary system calls while legal good both restricts the dangerous system calls and reduces the number of system calls compared to the default profile and the default profile represents neutral x neutral. Just like D&D character sheets. 
