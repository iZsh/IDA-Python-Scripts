# Basic Block IDA Python Module
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
# Basic Block Graph
#
####################################################
class BasicBlockNode:
  # ==========================================================================
  # Method: __init__()
  # ==========================================================================
  # Ident: unique integer to easily identify the node for pretty printing
  # (StartEA, EndEA): couple representing the starting EA and the ending EA
  #                   of the basic block. Those addresses represent resp.
  #                   the first and the last valid instruction of the basic
  #                   block. 
  # ==========================================================================
  def __init__(self, Ident, (StartEA, EndEA)):
    self.StartEA = StartEA
    self.EndEA = EndEA
    self.Ident = Ident
    self.NextNodes = set()
    self.PrevNodes = set()

  # ==========================================================================
  # Method: IsStart()
  # ==========================================================================
  # Description/Comment:
  # Test whether or not the node is a start node (i.e. it starts at the
  # beginning of the function)
  # ==========================================================================
  def IsStart(self):
    return get_func(self.StartEA).startEA == self.StartEA
    
  # ==========================================================================
  # Method: IsEnd()
  # ==========================================================================
  # Description/Comment:
  # Test whether or not the node is a end node (i.e. no next nodes)    
  def IsEnd(self):
    return len(self.NextNodes) == 0

  # ==========================================================================
  # Method: FindNode()
  # ==========================================================================
  # EA: Address of the instruction belonging to the basic block
  #     you're looking for
  # Return: The found node
  #
  # Description/Comment:
  # Find the node in the basic block graph whose EA address belongs to.
  # The search algorithm starts with the current nodes and thereafter
  # explores the "next nodes".
  # ==========================================================================
  def FindNode(self, EA):
    def FindNode_(self, EA, Visited):
      if self in Visited:
        return None
      Visited.add(self)
      if self.StartEA <= EA <= self.EndEA:
        return self
      for x in self.NextNodes:
        n = FindNode_(x, EA, Visited)
        if n:
          return n
      return None
    return FindNode_(self, EA, set())

  # ==========================================================================
  # Method: FindPathToRoot()
  # ==========================================================================
  # Return: list of nodes, starting from the root
  #
  # Description/Comment:
  # Starting from the current node, return any valid path to the "root"
  # (i.e. a "start node")
  # ==========================================================================
  def FindPathToRoot(self):
    def FindPathToRoot_(self, Visited):
      if self in Visited:
        return None
      Visited.add(self)
      if self.IsStart():
        return [self]
      for x in self.PrevNodes:
        l = FindPathToRoot_(x, Visited)
        if l:
          l.append(self)
          return l
      return None
    return FindPathToRoot_(self, set())

  # ==========================================================================
  # Method: FindEnd()
  # ==========================================================================
  # Return: the first found node
  #
  # Description/Comment:
  # Find any "end node", exploring the current node and thereafter the
  # "next nodes"    
  # ==========================================================================
  def FindEnd(self):
    def FindEnd_(self, Visited):
      if self in Visited:
        return None
      Visited.add(self)
      if self.IsEnd():
        return self
      for x in self.NextNodes:
        n = FindEnd_(x, Visited)
        if n:
          return n
      return None
    return FindEnd_(self, set())

  # ==========================================================================
  # Method: PrintNode()
  # ==========================================================================
  # Description/Comment:
  # Pretty Print the node    
  # ==========================================================================
  def PrintNode(self):
    print "Node %d = (StartEA:0x%x, EndEA:0x%x)" % (self.Ident, self.StartEA, self.EndEA)
    print "  Previous Nodes:"
    for x in sorted(self.PrevNodes, cmp = lambda x,y: cmp(x.Ident, y.Ident)):
      print "    Node %d" % x.Ident
    print "  Next Nodes:"
    for x in sorted(self.NextNodes, cmp = lambda x,y: cmp(x.Ident, y.Ident)):
      print "    Node %d" % x.Ident
 
  # ==========================================================================
  # Method: Dump()
  # ==========================================================================
  # Description/Comment:
  # Pretty print the whole graph       
  # ==========================================================================
  def Dump(self):
    def Dump_(self, Visited):
      if self in Visited:
        return
      Visited.add(self)
      self.PrintNode()
      for n in self.NextNodes:
        Dump_(n, Visited)
    Dump_(self, set())

# ============================================================================
# Function: BuildBasicBlockInfo()
# ============================================================================
# Description/Comment:
# Build the basic blocks information
# it returns two lists as a couple:
# - the BB EAs as (StartEA, EndEA) couple
# - the flow edges as (EA1, EA2)
# For example:
# [ [(StartEA1, EndEA1), (StartEA2, EndEA2)], [(EndEA1, StartEA2)] ]
#
# We could build a graph directly, but it could be convenient for ppl
# who just need some basic information (such as the number
# of BB, the number of edges and so on...)
#
# This function is mostly from openrce.org at
# http://www.openrce.org/articles/full_view/11
# (the cyclomatic complexity example), having its return value reworked
# ============================================================================
def BuildBasicBlockInfo(EA):

  f_start = get_func(EA).startEA
  f_end = FindFuncEnd(f_start)
    
  edges = set()
  boundaries = set((f_start,))
    
  # For each defined element in the function.
  for head in Heads(f_start, f_end):
    
    # If the element is an instruction
    if isCode(GetFlags(head)):
        
      # Get the references made from the current instruction
      # and keep only the ones local to the function.
      refs = CodeRefsFrom(head, 0)
      refs = set(filter(lambda x: x>=f_start and x<=f_end, refs))
            
      if refs:
        # If the flow continues also to the next (address-wise)
        # instruction, we add a reference to it.
        # For instance, a conditional jump will not branch
        # if the condition is not met, so we save that
        # reference as well.
        next_head = NextHead(head, f_end)
        if isFlow(GetFlags(next_head)):
          refs.add(next_head)
                
        # Update the boundaries found so far.
        boundaries.update(refs)
                            
        # For each of the references found, and edge is
        # created.
        for r in refs:
          # If the flow could also come from the address
          # previous to the destination of the branching
          # an edge is created.
          if isFlow(GetFlags(r)):
            edges.add((PrevHead(r, f_start), r))
          edges.add((head, r))

  # Let's build the list of (startEA, startEA) couples
  # for each basic block
  sorted_boundaries = sorted(boundaries, reverse = True)
  end_addr = PrevHead(f_end, f_start)
  bb_addr = []
  for begin_addr in sorted_boundaries:
    bb_addr.append((begin_addr, end_addr))
    # search the next end_addr which could be
    # farther than just the previous head
    # if data are interlaced in the code
    # WARNING: it assumes it won't epicly fail ;)
    end_addr = PrevHead(begin_addr, f_start)
    while not isCode(GetFlags(end_addr)):
      end_addr = PrevHead(end_addr, f_start)
  # And finally return the result
  bb_addr.reverse()
  return bb_addr, sorted(edges)

# ============================================================================
# Function: BuildBasicBlockGraph()
# ============================================================================
# Return: the first node of the graph
#
# Description/Comment:
# Build a graph of the basic blocks
# ============================================================================
def BuildBasicBlockGraph(EA):
  # local function helper
  def find_node(EA, Nodes):
    for n in Nodes:
      if n.StartEA <= EA <= n.EndEA:
        return n
    return None

  boundaries, edges = BuildBasicBlockInfo(EA)
  # build the nodes
  nodes = set()
  first_node = BasicBlockNode(len(nodes), boundaries.pop(0))
  nodes.add(first_node)
  for x in boundaries:
    nodes.add(BasicBlockNode(len(nodes), x))
  # build the edges
  # ~n^2 algorithm...
  # Hopefully there aren't too many nodes and edges ;)
  # no premature optimizations kthx
  for (src_ea, dest_ea) in edges:
    src_node = find_node(src_ea, nodes)
    dest_node = find_node(dest_ea, nodes)
    src_node.NextNodes.add(dest_node)
    dest_node.PrevNodes.add(src_node)
    
  return first_node
