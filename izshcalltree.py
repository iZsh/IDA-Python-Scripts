# Call Tree IDA Python Module
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

from idaapi import *
from idc import *
from idautils import *

####################################################
#
# Call Tree
#
####################################################
class CallTreeNode:
  # ===========================================================================
  # Method: __init__()
  # ===========================================================================
  # Name: Name of the function
  # EA: Starting address of the function
  # NextCallEA: Address where the subcall is being made
  # Parent: the parent node in the tree
  # ===========================================================================
  def __init__(self, Name, EA, NextCallEA, Parent = None):
    self.Children = []
    self.Parent = Parent
    self.Name = Name
    self.EA = EA
    self.NextCallEA = NextCallEA
    # We retrieve the SP delta at the next call address
    self.NextCallSPD = 0
    if NextCallEA:
      self.NextCallSPD = get_spd(get_func(NextCallEA), NextCallEA)

  # ===========================================================================
  # Method: Exists()
  # ===========================================================================
  # Name: The name of the function
  # NextCallEA: address where the subcall is being made  
  # Return a boolean
  #
  # Description/Comment:
  # Checking the NextCallSPD will enable us to analyze the
  # function call again in cases wherein the stack state
  # is not the same for multiple calls of the same
  # function.
  # ===========================================================================
  def Exists(self, Name, NextCallEA):
    NextCallSPD = 0
    if NextCallEA:
      NextCallSPD = get_spd(get_func(NextCallEA), NextCallEA)    
    if self.Name == Name and self.NextCallSPD == NextCallSPD:
      return True
    for c in self.Children:
      if c.Exists(Name, NextCallEA):
        return True
    return False

  # ===========================================================================
  # Method: FindAllPaths()
  # ===========================================================================
  # Return: List of list of (EA, Name, NextCallEA, NextCallSPD)
  #
  # Description/Comment:
  # Return the list of all the possible paths _up_ to this node (including it)
  # for each node (EA, Name, NextCallEA, NextCallSPD) is collected
  # ===========================================================================
  def FindAllPaths(self):
    info = (self.EA, self.Name, self.NextCallEA, self.NextCallSPD)
    if len(self.Children) == 0:
      return [[info]]
    paths = []
    for n in self.Children:
      subpaths = n.FindAllPaths()
      map(lambda p: p.append(info), subpaths)
      paths.extend(subpaths)
    return paths

  # ===========================================================================
  # Method: Dump()
  # ===========================================================================
  # Description/Comment:
  # Pretty print the tree - or ugly print... it depends on the point of view ;)
  # ===========================================================================
  def Dump(self, Space = 0, Threshold = 42):
    if Space > Threshold:
      return
    print (" " * Space + self.Name + " @" + hex(self.EA)
      + " (%xh @0x%x)" % (self.NextCallSPD, self.NextCallEA))
    for c in self.Children:
      c.Dump(Space + 1)

# ===========================================================================
# Function: BuildCallTree()
# ===========================================================================
# EA: address of the function
# NextCallEA: address where the subfunction is being called
# P = Parent node
# Debug = Enable debug messages
#
# Description/Comment:
# Build the call tree starting with the function at EA
# ===========================================================================
def BuildCallTree(EA, NextCallEA = BADADDR, P = None, Debug = False):
  name = GetFunctionName(EA)
  if not name:
    name = "loc_%x" % EA
  if P and P.Exists(name, NextCallEA):
    return None
  # Build the node  
  node = CallTreeNode(name, EA, NextCallEA, Parent = P)
  # Iterate through the xref
  for xref in CodeRefsTo(EA, 1):
    try:
      # Retrieve the EA of the calling function
      xref_f = get_func(xref).startEA
      if Debug:
        print ("[fun %s @0x%x]  fun %s @0x%x: calling %s @0x%x" 
          % (name, EA, GetFunctionName(xref_f), xref_f, name, xref))
      # Build the subtree recursively
      subtree = BuildCallTree(xref_f, xref, P = node, Debug = Debug)
      if subtree:
        node.Children.append(subtree)
        if Debug:
          print "[fun %s @0x%x]  Adding the following subtree:" % (name, EA)
          subtree.Dump()
          print "[fun %s @0x%x]  The new node looks like this:" % (name, EA)
          node.Dump()
    except:
      if Debug:
        print "[fun %s @0x%x]  [!] Problem getting func of %x" % (name, EA, xref)
  # Finally returns the result
  return node
 