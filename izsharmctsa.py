# Call Tree and Stack Analyzer IDA Python Script for ARM Processors
# Copyright (c) 2009 iZsh - izsh at iphone-dev.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# =============
#  Description
# =============
#
# Starting from a given function, it builds all the possible paths reaching
# it, and for each of these paths, it analyzes the stack content.
#
# =======
#  Usage
# =======
# Place the cursor _at the beginning_ of the function you want to start the
# analysis from, and execute this script (with Alt+9 by default).
# 
# You have to make sure all the functions which would need to be analyzed have
# to be actual IDA function (including the entry point function which
# usually set the initial stack pointer value).
# 
# You can also edit this script and change the main call from
# AnalyzeCallTreeStack(ea)
# to
# AnalyzeCallTreeStack(ea, AskAddr = True)
# 
# if you'd like the script to explicitly ask you for the initial stack pointer
# value.
#
# ==================
#  General Comments
# ==================
# 
# This is a script written for IDA Python to analyze a call tree as well as
# trying to extract the stack state of each function with a pure static
# analysis. This works only with ARM processors and although it has severe
# limitations it seems to work quite ok on both the 3G and 3GS iPhone bootrom :)
# This is mainly useful assisting exploit writing of buffer overflows.
# 
# This is my first Python _and_ IDA Python code, thus, if you feel I missed
# some nice Python features which would make the code more elegant or who knows
# what, feel free to drop me an email. Feel also free to drop me an email for
# any suggestions or insights to improve my ninja-skillz ;)
# 
# The call tree and basic block module should be generic enough to be usable
# in other projects/scripts (or epic fail, which wouldn't be that much
# surprising either :P ). The ARM stack analysis module is quite specific
# considering it's doing very sparse island parsing...
# 

from idc import *
from izsharmstackanalysis import *

####################################################
#
# Main
#
####################################################

ea = ScreenEA()
print "Call Tree and Stack Analyzer IDA Python Script for ARM Processors"
print "Copyright (c) 2009 iZsh - izsh at iphone-dev.com"
print "=" * 80
print "Analyze starts from 0x%x\n" % ea
print "=" * 80
AnalyzeCallTreeStack(ea)
