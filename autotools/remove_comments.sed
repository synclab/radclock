#!/usr/bin/sed -f

#< Remove C/C++ comments from files
# Another way to do it - adapted from a script found here
# http://sed.sourceforge.net/grabbag/scripts/remccoms1.sed
# to allow c++ // style comments to be removed
#
# c++ // comment removal code added KW 01/11/04
# comments added KW 02/11/04

# If pattern is not matched (i.e. line does not contain /*
# then branch to label :c
/\/\*/!bc

# Okay - line must contain /*, or we've branched here
# if line doesn't contain */ then append contents of next line to
# pattern space and continue - we must have got here by a branch
# to :a (or start of comment), so we can assume we're 
# processing a comment
:a
/\*\//!{
N
# branch back to :a to continue processing comment
ba
}
:c
# okay - not multiline comment - could be code, or single line
# comment

# replace single line comment with nothing
s:/\*.*\*/::

# replace // comment with nothing
s://.*$::g

